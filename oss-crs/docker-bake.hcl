# =============================================================================
# crs-multi-retrieval Docker Bake Configuration
# =============================================================================
#
# Builds the CRS base image with Python dependencies for multi-retrieval agent.
#
# Usage:
#   docker buildx bake prepare
#   docker buildx bake --push prepare   # Push to registry
# =============================================================================

variable "REGISTRY" {
  default = "ghcr.io/team-atlanta"
}

variable "VERSION" {
  default = "latest"
}

function "tags" {
  params = [name]
  result = [
    "${REGISTRY}/${name}:${VERSION}",
    "${REGISTRY}/${name}:latest",
    "${name}:latest"
  ]
}

# -----------------------------------------------------------------------------
# Groups
# -----------------------------------------------------------------------------

group "default" {
  targets = ["prepare"]
}

group "prepare" {
  targets = ["multi-retrieval-base"]
}

# -----------------------------------------------------------------------------
# Base Image
# -----------------------------------------------------------------------------

target "multi-retrieval-base" {
  context    = "."
  dockerfile = "oss-crs/base.Dockerfile"
  tags       = tags("multi-retrieval-base")
}
