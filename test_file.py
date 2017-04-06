#!/usr/bin/python
from sys import argv
from operator import itemgetter
from collections import Counter
from datetime import datetime
from datetime import timedelta
import re
import time

class LogAnalyzer(): #class to process log data
	
	def __init__(self,input_log, output_hosts, output_resources, output_hours, output_blocked):
		self.input_log = input_log
		self.output_hosts = output_hosts
		self.output_hours = output_hours
		self.output_resources = output_resources
		self.output_blocked = output_blocked
		hosts = []
		resources = {}
		self.cutoff_records = []
		self.sliding_window_counter = 0
		self.ip_map = {}
		with open(self.input_log,"r") as f: #read input line by line and update on the fly
			for line in f:	                     
				if not self.record_validity(line):
					continue
				# populate the hosts dictionary
				hosts.append(self.ip_address)

				# populate the resources dictionary 
				if self.resource not in resources:
					resources[self.resource] = self.reply_bytes
				else:
					resources[self.resource] += self.reply_bytes 
				date_time_object = self.parse_time_period(self.time_period)		
				self.add_to_sliding_window(date_time_object)
				self.find_failed_logins(line)	
		self.identify_active_hosts(hosts)
		self.identify_resources(resources)
		self.identify_top_hours()
		self.mine_failed_logins()
		
	def record_validity(self,line):         #check the validity of record and set fields if valid
		regex = r'^(?P<host>\S+) - - \[(?P<time>.+)\] "(?P<request>.+)" (?P<status>[\d]+) (?P<size>\S+)$'
		match = re.search(regex, line)
		if match is None:
			return False
		else:
			res = match.groupdict()
			if res["size"] == "-":
				res["size"] = 0
			else:
				res["size"] = int(res["size"]) 
			self.ip_address = res["host"]
			self.time_period = res["time"]
			try:
				self.resource = res["request"].split(" ")[1]
			except IndexError as err:
				return False
			self.reply_http_code = int(res["status"])
			self.reply_bytes = res["size"]
			return True

	def identify_active_hosts(self,hosts): #method to write top 10 hosts to file
		c = Counter(hosts)
		active_hosts = list(c.most_common(10))
		with open(self.output_hosts,"w") as h:
			for i in active_hosts:
				h.write(i[0]+","+str(i[1])+"\n")
	
	def identify_resources(self,resources): #method to write top 10 used resources to file
		sorted_resources = sorted(resources.items(), key = itemgetter(1), reverse = True)
		with open(self.output_resources, "w") as r:
			for i in sorted_resources[:10]:
				r.write(i[0]+"\n")

	def parse_time_period(self, time_period): #parse given timestamp string into Python datetime
		try:
			new_time_period = time_period.split(" ")[0]
		except IndexError as e:
			pass 
		datetime_object = datetime.strptime(new_time_period, '%d/%b/%Y:%H:%M:%S') #all records have same timezone, ignore it.
		return datetime_object

	def add_to_sliding_window(self, date_time_object): #add records to sliding window
		if self.sliding_window_counter == 0:
			self.sliding_window_head = self.time_period
			self.cutoff_time = date_time_object + timedelta(minutes = 60) 
			self.sliding_window_counter = 1
		else:
			if date_time_object < self.cutoff_time:
				self.sliding_window_counter += 1
			else:
				self.cutoff_records.append((self.sliding_window_head,self.sliding_window_counter))
				self.sliding_window_counter = 0

	def identify_top_hours(self): #identify busiest hours
		self.cutoff_records.sort(key = itemgetter(1), reverse = True) #sort based on record count
		with open(self.output_hours, "w") as t:
			for tp in self.cutoff_records[:10]:
				t.write(tp[0]+", "+str(tp[1])+"\n")

	def find_failed_logins(self, line): #identify records with http status code 401
			if self.ip_address not in self.ip_map:
				if self.reply_http_code == 401:
					self.ip_map[self.ip_address] = [line]
				else:
					pass
			else:
				self.ip_map[self.ip_address].append(line)				
				
	def mine_failed_logins(self): #identify ip addresses to be blocked
		with open(self.output_blocked, "w") as ob:
			for ip in self.ip_map:
				final_list = self.check_blocking_condition(ip)
				for item in final_list:
					ob.write(item)

	def check_blocking_condition(self,ip): #create lists of ip addresses to be blocked
		ip_block_check = []
		return_list = []
		for record in self.ip_map[ip]:
			regex = r'^(?P<host>\S+) - - \[(?P<time>.+)\] "(?P<request>.+)" (?P<status>[\d]+) (?P<size>\S+)$'
			match = re.search(regex, record)
			res = match.groupdict()
			timestamp = res["time"]
			ip_block_check.append([record, self.parse_time_period(timestamp), res["status"]])
		head_time = ip_block_check[0][1]
		login_fail_counter = 1
		for record_list in ip_block_check[1:]:
			if record_list[1] - head_time < timedelta(seconds = 20) and record_list[2] == 401:
				login_fail_counter += 1
		if login_fail_counter > 2 :
			return_list.append(ip_block_check[login_fail_counter-1][0])
		for pending_records in ip_block_check[login_fail_counter:]:
			if pending_records[1] - head_time < timedelta(minutes = 5):
				return_list.append(pending_records[0])
		return return_list			

if __name__ == "__main__":
	start_time = time.time()
	LogAnalyzer(argv[1],argv[2],argv[3],argv[4],argv[5])
	print ("--- %s seconds ---" % (time.time() - start_time))
