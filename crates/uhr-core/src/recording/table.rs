use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arrow_array::types::{UInt32Type, UInt64Type};
use arrow_array::{
    Array, ArrayRef, ArrowPrimitiveType, BooleanArray, ListArray, PrimitiveArray, RecordBatch,
    StringArray, UInt32Array, UInt64Array,
};
use arrow_buffer::OffsetBuffer;
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;

pub(super) struct Column {
    name: &'static str,
    array: ArrayRef,
    nullable: bool,
}

impl Column {
    pub fn u32(name: &'static str, values: Vec<u32>) -> Self {
        Self::new(name, Arc::new(UInt32Array::from(values)), false)
    }

    pub fn u64(name: &'static str, values: Vec<u64>) -> Self {
        Self::new(name, Arc::new(UInt64Array::from(values)), false)
    }

    pub fn optional_u32(name: &'static str, values: Vec<Option<u32>>) -> Self {
        Self::new(name, Arc::new(UInt32Array::from(values)), true)
    }

    pub fn optional_u64(name: &'static str, values: Vec<Option<u64>>) -> Self {
        Self::new(name, Arc::new(UInt64Array::from(values)), true)
    }

    pub fn string(name: &'static str, values: Vec<&str>) -> Self {
        Self::new(name, Arc::new(StringArray::from(values)), false)
    }

    pub fn optional_string(name: &'static str, values: Vec<Option<&str>>) -> Self {
        Self::new(name, Arc::new(StringArray::from(values)), true)
    }

    pub fn bool(name: &'static str, values: Vec<bool>) -> Self {
        Self::new(name, Arc::new(BooleanArray::from(values)), false)
    }

    pub fn u32_lists(name: &'static str, lists: &[Vec<u32>]) -> Self {
        let item = Arc::new(Field::new("item", DataType::UInt32, false));
        let offsets = OffsetBuffer::from_lengths(lists.iter().map(Vec::len));
        let values = UInt32Array::from(lists.concat());
        let array = ListArray::new(item, offsets, Arc::new(values), None);
        Self::new(name, Arc::new(array), false)
    }

    fn new(name: &'static str, array: ArrayRef, nullable: bool) -> Self {
        Self {
            name,
            array,
            nullable,
        }
    }
}

pub(super) fn write(path: &Path, columns: Vec<Column>) -> Result<()> {
    let fields: Vec<Field> = columns
        .iter()
        .map(|c| Field::new(c.name, c.array.data_type().clone(), c.nullable))
        .collect();
    let schema = Arc::new(Schema::new(fields));
    let arrays = columns.into_iter().map(|c| c.array).collect();
    let batch = RecordBatch::try_new(schema.clone(), arrays)?;

    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
        .build();
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut writer = ArrowWriter::try_new(file, schema, Some(properties))?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(())
}

/// A table read back from disk. Getters fail on missing columns, wrong
/// types and unexpected nulls, so callers get plain values.
pub(super) struct Table {
    name: String,
    batch: RecordBatch,
}

impl Table {
    pub fn read(path: &Path) -> Result<Self> {
        let name = path.display().to_string();
        let file = File::open(path).with_context(|| format!("opening {name}"))?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)
            .with_context(|| format!("reading {name}"))?;
        let schema = builder.schema().clone();
        let batches = builder
            .build()?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("reading {name}"))?;
        let batch = arrow_select::concat::concat_batches(&schema, &batches)?;
        Ok(Self { name, batch })
    }

    pub fn len(&self) -> usize {
        self.batch.num_rows()
    }

    pub fn u32(&self, column: &str) -> Result<Vec<u32>> {
        self.required::<UInt32Type>(column)
    }

    pub fn u64(&self, column: &str) -> Result<Vec<u64>> {
        self.required::<UInt64Type>(column)
    }

    pub fn optional_u32(&self, column: &str) -> Result<Vec<Option<u32>>> {
        Ok(self.primitive::<UInt32Type>(column)?.iter().collect())
    }

    pub fn optional_u64(&self, column: &str) -> Result<Vec<Option<u64>>> {
        Ok(self.primitive::<UInt64Type>(column)?.iter().collect())
    }

    pub fn string(&self, column: &str) -> Result<Vec<String>> {
        let array = self.array::<StringArray>(column)?;
        self.check_no_nulls(column, array)?;
        Ok(array.iter().flatten().map(str::to_owned).collect())
    }

    pub fn optional_string(&self, column: &str) -> Result<Vec<Option<String>>> {
        let array = self.array::<StringArray>(column)?;
        Ok(array.iter().map(|v| v.map(str::to_owned)).collect())
    }

    pub fn bool(&self, column: &str) -> Result<Vec<bool>> {
        let array = self.array::<BooleanArray>(column)?;
        self.check_no_nulls(column, array)?;
        Ok(array.iter().flatten().collect())
    }

    pub fn u32_lists(&self, column: &str) -> Result<Vec<Vec<u32>>> {
        let array = self.array::<ListArray>(column)?;
        self.check_no_nulls(column, array)?;
        let values = array
            .values()
            .as_any()
            .downcast_ref::<UInt32Array>()
            .with_context(|| format!("{}: column {column} is not a list of u32", self.name))?;
        self.check_no_nulls(column, values)?;
        let values = values.values();
        Ok(array
            .offsets()
            .windows(2)
            .map(|w| values[w[0] as usize..w[1] as usize].to_vec())
            .collect())
    }

    fn required<T: ArrowPrimitiveType>(&self, column: &str) -> Result<Vec<T::Native>> {
        let array = self.primitive::<T>(column)?;
        self.check_no_nulls(column, array)?;
        Ok(array.values().to_vec())
    }

    fn primitive<T: ArrowPrimitiveType>(&self, column: &str) -> Result<&PrimitiveArray<T>> {
        self.array::<PrimitiveArray<T>>(column)
    }

    fn array<T: Array + 'static>(&self, column: &str) -> Result<&T> {
        let array = self
            .batch
            .column_by_name(column)
            .with_context(|| format!("{}: missing column {column}", self.name))?;
        array.as_any().downcast_ref::<T>().with_context(|| {
            format!(
                "{}: column {column} has unexpected type {}",
                self.name,
                array.data_type()
            )
        })
    }

    fn check_no_nulls(&self, column: &str, array: &dyn Array) -> Result<()> {
        if array.null_count() > 0 {
            bail!("{}: column {column} must not contain nulls", self.name);
        }
        Ok(())
    }
}
