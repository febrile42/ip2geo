<?php
/**
 * Retired in v5.0.0 (IPG-10 S4). Its only caller was the Threat Report page,
 * which v5 removed, so it had no legitimate traffic left. Returns 410 for every
 * request and never touches the database.
 *
 * The opt-in ingestion code (community_cidr_stats / community_ip_stats) lives
 * in git history before this change, if Open Question 4 keeps the block list.
 */

http_response_code(410);
header('Content-Type: application/json');
echo json_encode(['error' => 'gone']);
