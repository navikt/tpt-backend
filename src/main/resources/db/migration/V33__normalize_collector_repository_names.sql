WITH ranked_checks AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY CASE WHEN POSITION('/' IN repo) = 0 THEN 'navikt/' || repo ELSE repo END,
                            check_name
               ORDER BY updated_at DESC, POSITION('/' IN repo) DESC, id DESC
           ) AS position
    FROM datacollector_checks
)
DELETE FROM datacollector_checks
WHERE id IN (SELECT id FROM ranked_checks WHERE position > 1);

UPDATE datacollector_checks
SET repo = 'navikt/' || repo
WHERE POSITION('/' IN repo) = 0;

-- A GitHub callback replaces the whole snapshot, including teams and vulnerabilities.
WITH ranked_repositories AS (
    SELECT name_with_owner,
           ROW_NUMBER() OVER (
               PARTITION BY CASE WHEN POSITION('/' IN name_with_owner) = 0
                                 THEN 'navikt/' || name_with_owner ELSE name_with_owner END
               ORDER BY updated_at DESC NULLS LAST, POSITION('/' IN name_with_owner) DESC
           ) AS position
    FROM github_repositories
)
DELETE FROM github_repositories
WHERE name_with_owner IN (SELECT name_with_owner FROM ranked_repositories WHERE position > 1);

-- Create the new parent keys before moving vulnerabilities to satisfy the foreign key.
INSERT INTO github_repositories (name_with_owner, nais_teams, created_at, updated_at)
SELECT 'navikt/' || name_with_owner, nais_teams, created_at, updated_at
FROM github_repositories
WHERE POSITION('/' IN name_with_owner) = 0;

UPDATE github_vulnerabilities
SET name_with_owner = 'navikt/' || name_with_owner
WHERE POSITION('/' IN name_with_owner) = 0;

DELETE FROM github_repositories
WHERE POSITION('/' IN name_with_owner) = 0;
