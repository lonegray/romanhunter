'''
    Purpose:
    This script coupled with a WG602V4 Netgear Wireless AP will act as a sinkhole to detect hackers actively attacking this wireless network and liely the adjacent ones.  
    If this one is attacked one can rest assured they should be looking for this same data obtained on adjacent networks as well as more heavily scrutinizing the wireless AP data.
    This system is meant to give people an idea of how to detect rogue connections on their networks.  This is not meant to be a production tool in any way.
        
    Functionality:
    This script will POLL and scrape MAC address data from a Netgear WG602V4.  If the script finds a MAC listed in the scraped data it will change the 
    password on the router and reboot it.  In this version, the ESSID will remain unchanged.  There is a significant psychological aspect to the strategies that can be used here.
    and they must be taken into consideration.  Examples are: easyness of password, kind of password (don't make it hackersrjerks), don't make the password too complex, the name of the 
    ESSID (it must be juicy), the signal strength should be stronger than any of the other adjacent routers, etc... (either user powerfull one or one with adjustable strength)

    Future Functionality:
    - MAC address lookups describing the device (this turns the sinkhole into a honeypot if this device is communicating externally on the network)
    - Estimated direction and estimated distance to location of attacker (other sensors or antennaes would be required for this functionality)
    - Extend to UBNT devices (for the physical wireless race condition of the strongest signal in a mesh, this would also require a client side application that would contain the sinkhole data)
    - Implement Python Threading (track mac attached for more than 2-3 seconds, experimentally determine the time)

    List of Tools Used for Development:
    - http://www.voiproblem.com/emulators/Netgear/
    - http://www.python-requests.org
    - http://www.tuffcode.com/download.html (OS X)(http protocol analyzer - requests/responses for reverse engineering router logic) (fiddler on Windows)
    - Developed on OS X Mountain Lion
    - Python 2.7
    - Aptana (Python IDE for OS X Mountain Lion)
    - WG602V4 Netgear Router (Best Buy)
    - Samsung S3 phone for making wireless network connections (simulating attacker)
    - The greatest programmer in the world!!!!
    
    Developed
        by:  lonegray@gmail.com
        on:  20130920 (for ARM Tech Con 2013)
    
    The BSD license will apply to this software.  The developer is not responsible for any defects or issues that may arrise from the use of this software.
    
    Assumptions:
    - Wireless hackers are very brave as there are not many honepots out there for them or common ways to detect them
    - They are physically invisible to the admins giving them less fear and emboldening them

    Discussion Topics:
    - Could be packaged in a PVC pipe to monitor hotspots for hackers and used with metrics could be an additional data stream for engineers when selecting locations for
      infrastructure and determining threat ratings and models.
      
    Revisions:
    - V3a was the original release
    - V3c Adding check for 'authorization' on the line w/the mac address, just some text processing that will show they are authorzied versus associated, also logging both mac's     
'''

#------------------------------------------------------------------------------
#    generateNewWIFIPW()
#------------------------------------------------------------------------------
def generateNewWIFIPW():
    #Generate a new password to replace the existing wireless pw:
    #Scan the log file for the last PW used
    #if the PW file does not exist then start w/the first pw on the list
    DEBUGGING=0
    
    #Open the file and read in the list of PW's
    listPWs=[]
    with open('pw_list.txt') as f:
        for line in f:
            listPWs.append(line)
    f.closed

    #WARNING: This section needs work as it is not production ready, these log entires are not yet rotated or checked and can grow to unlimited size!
    #open the log file and get the last entry that contains the word: wifi   ... the last one is the one we are after.
    regExpression=' to: '
    with open('romanHunterv3.txt') as f:
        for line in f:
            #check to see if this one contains wifi:
            match=re.search(regExpression, line)
            if match:
                pwUsed=line[match.end():] 
                
        if DEBUGGING:
            print "last pw used is: ", pwUsed.rstrip('\n')
    
    index=0
    try:
        #if the pw is in the file, use the next one
        index=listPWs.index(pwUsed)

        #what if we are at the end of the list ... then rotate to the front
        sizeOfList=len(listPWs)
        if sizeOfList==index+1:
            #The pw was the last item on the list, so wrap the list back to the first:
            index=1
        pw2Return=listPWs[index+1]
    except:
        #the pw was not found in the list:
        pw2Return=listPWs[0]

    if DEBUGGING:
        print 'pw to return: ', pw2Return
        
    logger.error("Changing pw from: "+pwUsed+" to: "+pw2Return)
    return pw2Return



#------------------------------------------------------------------------------
#    Function to change the pw on the wireless IF of the router detects a connection

#    PREREQUISITES: 
#    1 the router must have already have a PW (wpa2) set in the wireless security settings.
#    2 Take a backup of the firmware on the router to be used for making a whirlpool hash for validation.
#------------------------------------------------------------------------------
def changePassword(username, password, logger):
    DEBUGGING=0
    URL4APPW="http://192.168.0.227/cgi-bin/security.cgi"        #URL for APplication PassWord  (acronym of variable APPW)

    newWIFIPW = generateNewWIFIPW()

    #Create variables we need to post to the Netgear Router:
    vlpayload={'setobject_security_type':'4', 'setobject_wpaspskPhrase':newWIFIPW}

    try:
        r0=requests.post(URL4APPW, vlpayload, auth=(username, password))
    except:
        print 'error 200, error opening URL: ', URL4APPW
        logger.error("Error 200, error opening url - "+ URL4APPW)

    if DEBUGGING:    
        print "result: ", r0.text    
        print "returned: ", r0.status_code
    
    #Verify the return code is 200, if not throw and error and alert someone after a 2nd attempt
    if r0.status_code != 200:
        if DEBUGGING:
            print "\n [+] Status code was not 200, it was: ", r0.status_code
        
        #log the status code error or throw and error.
        logger.error("status code was not 200, it was: "+ r0.status_code)

#------------------------------------------------------------------------------
#    check4ConnectionsR()   The 'R' here implies this function uses the requests library instead of URLLIB, URLLIB2, URLLIB3
#------------------------------------------------------------------------------
def check4ConnectionsR(url, username, password, logger):
    DEBUGGING=0
    wg602=1                                                 #WG602v4
    ubnt=0                                                  #use the ubiquity interface (Ubiquity Bullet2HP or M5)
    url1=""
    username1=""
    password1=""
    repattern='([0-9A-F]{2}[:-]){5}([0-9A-F]{2})'           #RE Pattern for a MAC Address:
    macList = []                                            #List container for the mac addresses so we can track them for over 2 seconds.

    #Static RE search patterns for WG602 Netgear AP (from stalist.html):
    assocLine="var assoc_list='"
    authoList="var autho_list='"

    #This section is for a quick ability to switch devices for testing in different locations
    #The other implications here would be that one could also monitor several devices at the same time
    #with slight modifications here.
    if 1==wg602:
        url1=url
        username1=username
        password1=password
        
    elif 1==ubnt:
        url1="url from ubnt device"
    else:
        url1=url
        username1=username
        password1=password

    if DEBUGGING:
        print "URL1: ", url1
        print "username1: ", username1
        print "password1: ", password1

    #Scrape the router page that displays the MAC addresses
    try:
        r=requests.get(url1, auth=(username1, password1))
    except:
        print "error 100 opening URL"
        logger.error("Error 100, could not open URL")
    
    if DEBUGGING:
        #print "result is: ", r.text
        print "status code: ", r.status_code
    
    #This section will detect and extract the MAC address if one found.
    #WARNING: This script may not properly handle multiple MACs being present at the same time, as this behavior should be very rare it was not tested.
    thePage = r.text
    entirePage = thePage.split('\n')                                 #Break the monolithic text into individual lines
    macFound=''
    matchFound=0
    printed=0
    for line in entirePage:
        '''
        Search for the two lines lines (the mac is a dynamic field), we may also want to log the associations (attempted connections)
        var assocList='assoclist 88:32:9B:7B:A2:D4';
        var authoList='autho_sta_list 88:32:9B:7B:A2:D4';
        '''
        
        matchMac=re.search(repattern, line)
        matchAuth=re.search(authoList, line)
        if matchMac and matchAuth:                                  #the line contained a mac, now check it for the author string
            '''
            match=re.search()
            if match:
                matchFound=1
                if DEBUGGING:
                    print "authoList hit found on this line: ", line
            '''
            match1=re.search(repattern, line)
            if match1:
                matchFound=1
                macAddress=line[match1.start():match1.end()]        #Slice the MAC address out of the line
                if DEBUGGING:
                    print "\n\nmacAddress from line: authoList: ", macAddress, "\n\n"
                if not printed:
                    printed=1
                    print "\n", macAddress, "\n"
                macFound=macAddress
    
    if 1==matchFound:
        logEntry="found: "+macFound
        logger.error(logEntry)
        macList.append(macFound)
        changePassword(username, password, logger)

#------------------------------------------------------------------------------
#    MAIN()
#------------------------------------------------------------------------------
if __name__ == '__main__':
    import requests, re, logging, time, sys
    DEBUGGING=0
    FOREVER=1

    counter=0
    url = "http://192.168.0.227/cgi-bin/stalist.html"       #URL for displaying connected devices MAC addresses on Netgear WG602 on best buy shelf 20130902
    username = 'admin'                                      #realm login for the router
    password = 'password'                                   #realm password for the router
    logFileName = 'romanHunterLog.txt'                      #path to logging file
    
    #Logger Setup:
    #http://docs.python.org/release/2.3.5/lib/node304.html
    logger=logging.getLogger('romanHunterv3')
    logHdlr = logging.FileHandler('./romanHunterv3.txt')
    logFormatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    logHdlr.setFormatter(logFormatter)
    logger.addHandler(logHdlr)
    logger.setLevel(logging.WARNING)
    
    print "Application Started\n"
    while FOREVER:
        if counter > 40:                                    #This section, including the else and counter increment are for printing the heartbeat section.
            counter=0
            sys.stdout.write('\n.')
        else:
            sys.stdout.write('.')
        counter=counter+1
        check4ConnectionsR(url, username, password, logger)
        time.sleep(1)
