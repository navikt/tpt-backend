-- Drop nvd_sync_status table
-- Leader election via Kubernetes handles sync coordination, making this table unnecessary

DROP TABLE IF EXISTS nvd_sync_status;

