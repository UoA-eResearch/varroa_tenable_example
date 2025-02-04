import tenable_helpers
import varroa_helpers


def main():
    # Check we have the required Nectar Cloud credentials
    has_env_vars = varroa_helpers.openstack_check_env_vars()
    if not has_env_vars:
        print("[!] Missing OpenStack credentials... Exiting.")
        exit()

    # Check we have the required Tenable Cloud credentials
    has_env_vars = tenable_helpers.tenable_check_env_vars()
    if not has_env_vars:
        print("[!] Missing Tenable credentials... Exiting.")
        exit()

    # Get all vulnerability findings for:
    # - When the finding is in the specified CIDR range
    # - When the finding is password-based SSH access
    print("[*] Fetching vulnerabilities from Tenable...")
    findings = tenable_helpers.get_findings_based_on_cidr_and_vulns()

    print(f"[*] Total found: {len(findings)}")

    for finding in findings:
        print(f"[*] Processing: {finding['ip_address']}...")

        # Get the instance ID and project ID based on the IP address and date
        lookup_result = varroa_helpers.get_instance_based_on_ip_history(finding["ip_address"], finding["last_found"])
        if lookup_result[0] is None:
            print("    [!] No instance found... Skipping.")
            continue
        else:
            print("    [*] Found instance...")
            finding["instance_id"] = lookup_result[0]
            finding["project_id"] = lookup_result[1]

        # # Check if the security risk already exists
        # security_risk_exists = varroa_helpers.check_security_risk_exists(finding)
        # if security_risk_exists:
        #     print("    [!] Security risk already exists... Skipping.")
        #     continue
        # else:
        #     print("    [*] Security risk does not exist...")

        # Create the security risk
        result = varroa_helpers.create_security_risk(finding)
        if result:
            print("    [*] Security risk created.")
        else:
            print("    [!] Failed to create security risk.")


if __name__ == "__main__":
    main()
