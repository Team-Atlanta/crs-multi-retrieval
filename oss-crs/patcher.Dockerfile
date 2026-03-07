# =============================================================================
# crs-multi-retrieval Patcher Module
# =============================================================================
# RUN phase: Receives POVs, generates patches using Multi Retrieval agent,
# tests them using the snapshot image for incremental rebuilds.
#
# Uses host Docker socket (mounted by framework) to access snapshot images.
# =============================================================================

# These ARGs are required by the oss-crs framework template
ARG target_base_image
ARG crs_version

FROM multi-retrieval-base

# Install libCRS (CLI + Python package)
COPY --from=libcrs . /libCRS
RUN pip3 install /libCRS \
    && python3 -c "from libCRS.base import DataType; print('libCRS OK')"

# Install crs-multi-retrieval package (patcher + agents + crete)
COPY pyproject.toml /opt/crs-multi-retrieval/pyproject.toml
COPY patcher.py /opt/crs-multi-retrieval/patcher.py
COPY agents/ /opt/crs-multi-retrieval/agents/
COPY crete/ /opt/crs-multi-retrieval/crete/
RUN pip3 install /opt/crs-multi-retrieval

CMD ["run_patcher"]
