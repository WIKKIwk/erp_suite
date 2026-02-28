#!/usr/bin/env bash
set -euo pipefail

# Local smoke test for ESS security log pipeline.
# Usage:
#   ./deploy/scripts/local_poligon_smoke.sh [site]

SITE="${1:-erp.localhost}"
TEST_IP="${ESS_TEST_IP:-203.0.113.88}"
TEST_USER="${ESS_TEST_USER:-poligon@test.local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="${ESS_BENCH_DIR:-}"

if [[ -z "${BENCH_DIR}" ]]; then
	CANDIDATE_DIR="${SCRIPT_DIR}"
	while [[ "${CANDIDATE_DIR}" != "/" ]]; do
		if [[ -d "${CANDIDATE_DIR}/sites" && -d "${CANDIDATE_DIR}/apps" ]]; then
			BENCH_DIR="${CANDIDATE_DIR}"
			break
		fi
		CANDIDATE_DIR="$(dirname "${CANDIDATE_DIR}")"
	done
fi

if [[ -z "${BENCH_DIR}" || ! -d "${BENCH_DIR}/sites" ]]; then
	echo "Could not detect bench directory. Set ESS_BENCH_DIR explicitly."
	exit 1
fi

cd "${BENCH_DIR}"

echo "[1/3] Writing synthetic security events to site: ${SITE}"
for i in 1 2 3 4 5; do
	bench --site "${SITE}" execute \
		erpnext_security_suite.erpnext_security_suite.security_v3.services.audit.log_security_event \
		--kwargs "{
			\"subject\": \"Failed login attempt detected\",
			\"status\": \"Failed\",
			\"content\": \"identity=${TEST_USER} failed_count=${i}\",
			\"user\": \"${TEST_USER}\",
			\"ip_address\": \"${TEST_IP}\",
			\"event_type\": \"login_failed_attempt\"
		}" >/dev/null
done

bench --site "${SITE}" execute \
	erpnext_security_suite.erpnext_security_suite.security_v3.services.audit.log_security_event \
	--kwargs "{
		\"subject\": \"Request limit exceeded\",
		\"status\": \"Failed\",
		\"content\": \"identity=${TEST_IP} path=/api/resource/User\",
		\"user\": \"Guest\",
		\"ip_address\": \"${TEST_IP}\",
		\"event_type\": \"request_limit_exceeded\"
	}" >/dev/null

LOG_PATH="${BENCH_DIR}/sites/${SITE}/logs/ess_security.log"
echo "[2/3] Last lines from ${LOG_PATH}"
tail -n 10 "${LOG_PATH}" || true

echo "[3/3] If fail2ban is installed, validate regex manually:"
echo "sudo fail2ban-regex ${LOG_PATH} /etc/fail2ban/filter.d/erpnext-security-login.conf"
echo "sudo fail2ban-regex ${LOG_PATH} /etc/fail2ban/filter.d/erpnext-security-api.conf"
