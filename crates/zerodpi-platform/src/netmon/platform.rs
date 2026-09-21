//! Native event sources. Fleshed out in the Linux and Windows tasks.

use std::sync::Arc;

use anyhow::Result;

use super::{NoopWaker, PollOnlySource, SourceParts};

pub(crate) fn source() -> Result<SourceParts<PollOnlySource>> {
    Ok(SourceParts {
        source: PollOnlySource,
        waker: Arc::new(NoopWaker),
    })
}
