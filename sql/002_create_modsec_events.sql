CREATE TABLE IF NOT EXISTS modsec_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    attack_event_id BIGINT UNSIGNED NULL,

    timestamp DATETIME NULL,
    source_ip VARCHAR(45) NULL,
    method VARCHAR(16) NULL,
    uri TEXT NULL,
    status INT NULL,
    bytes_sent BIGINT NULL DEFAULT 0,
    request_time DOUBLE NULL DEFAULT 0,

    user_agent TEXT NULL,
    user_agent_len INT NULL DEFAULT 0,
    uri_len INT NULL DEFAULT 0,

    severity VARCHAR(32) NULL,
    severity_score INT NULL DEFAULT 0,
    rule_id VARCHAR(64) NULL,
    matched_data TEXT NULL,
    msg TEXT NULL,
    is_blocked TINYINT(1) NOT NULL DEFAULT 0,
    rule_count INT NOT NULL DEFAULT 0,

    has_sqli TINYINT(1) NOT NULL DEFAULT 0,
    has_xss TINYINT(1) NOT NULL DEFAULT 0,
    has_suspicious_path TINYINT(1) NOT NULL DEFAULT 0,
    has_path_traversal TINYINT(1) NOT NULL DEFAULT 0,
    has_command_injection TINYINT(1) NOT NULL DEFAULT 0,
    has_cve_2022_24181 TINYINT(1) NOT NULL DEFAULT 0,
    missing_csrf_token TINYINT(1) NOT NULL DEFAULT 0,
    has_suspicious_referer TINYINT(1) NOT NULL DEFAULT 0,
    has_cve_2024_xss_privesc TINYINT(1) NOT NULL DEFAULT 0,
    has_privesc_attempt TINYINT(1) NOT NULL DEFAULT 0,
    has_cve_2021_32626 TINYINT(1) NOT NULL DEFAULT 0,

    model_prediction TINYINT(1) NULL,
    model_probability DECIMAL(6,5) NULL,

    human_label TINYINT(1) NULL,
    label_source ENUM('telegram','manual','weak_auto') NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    labeled_at DATETIME NULL,

    PRIMARY KEY (id),

    KEY idx_modsec_attack_event_id (attack_event_id),
    KEY idx_modsec_timestamp (timestamp),
    KEY idx_modsec_source_ip (source_ip),
    KEY idx_modsec_human_label (human_label),
    KEY idx_modsec_model_probability (model_probability)
) ENGINE=InnoDB;
