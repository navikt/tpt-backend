ALTER TABLE datacollector_checks ADD CONSTRAINT unique_results UNIQUE(check_name, repo);
