DOCUMENTATION

1. LogAnalyzer: Class that initializes necessary variables and data structures and maintains methods

2. init: Constructor to read line by line and update statistics on the fly

3. record_validity: Method to check validity of record 

4. identify_active_hosts: Method to identify top 10 most active hosts/IP addresses

5. identify_resources: Method to identify top 10 resources on the site that consume most bandwitdth

6. parse_time_period: A helper method to parse timestamp and create Python datetime object

7. add_to_sliding_window: A helper method to maintain a sliding window in order to identify top 10 busiest
			  durations

8. identify_top_hours: Method to identify top 10 busiest time periods

9. find_failed_logins: A helper method to populate a dictionary with ip address as key and 
			its failed login attempts as list of values 

10. mine_failed_logins: Method to identify ip addresses to be blocked

11. check_blocking_condition: A helper method to check if a particular ip has to be blocked


NOTE: Two of the test cases fail when running run_tests.sh, but the code does work on the main dataset.
