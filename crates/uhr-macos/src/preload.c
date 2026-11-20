// Loaded by dyld into each program uhr launches, and the programs they
// launch, through DYLD_INSERT_LIBRARIES. It sends uhr the process's task
// port, which a process can always give away, so uhr samples it without
// root, then waits for uhr to start sampling before the program's own code
// runs.

#include <mach/mach.h>
#include <stdlib.h>

// From <servers/bootstrap.h>, which only the full SDK has.
extern mach_port_t bootstrap_port;
kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

// Matches HELLO in launch.rs.
#define UHR_HELLO 0x75687231

struct hello {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t task;
};

__attribute__((constructor)) static void uhr_hello(void) {
    const char *service = getenv("UHR_SERVICE");
    if (service == NULL) {
        return;
    }
    mach_port_t uhr = MACH_PORT_NULL;
    // Fails once uhr has stopped, and the program runs on unrecorded.
    if (bootstrap_look_up(bootstrap_port, service, &uhr) != KERN_SUCCESS) {
        return;
    }
    mach_port_t reply = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply) != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), uhr);
        return;
    }
    struct hello hello = {0};
    hello.header.msgh_bits =
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;
    hello.header.msgh_size = sizeof hello;
    hello.header.msgh_remote_port = uhr;
    hello.header.msgh_local_port = reply;
    hello.header.msgh_id = UHR_HELLO;
    hello.body.msgh_descriptor_count = 1;
    hello.task.name = mach_task_self();
    hello.task.disposition = MACH_MSG_TYPE_COPY_SEND;
    hello.task.type = MACH_MSG_PORT_DESCRIPTOR;
    kern_return_t sent = mach_msg(&hello.header, MACH_SEND_MSG, sizeof hello, 0, MACH_PORT_NULL,
                                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (sent == MACH_MSG_SUCCESS) {
        // If uhr ends without answering, the kernel's notice that the
        // answer can no longer come ends the wait.
        struct {
            mach_msg_header_t header;
            char room[256];
        } answer;
        mach_msg(&answer.header, MACH_RCV_MSG, 0, sizeof answer, reply, MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);
    }
    mach_port_mod_refs(mach_task_self(), reply, MACH_PORT_RIGHT_RECEIVE, -1);
    mach_port_deallocate(mach_task_self(), uhr);
}
