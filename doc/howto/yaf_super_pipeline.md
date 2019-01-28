Configuring YAF with super_mediator and Analysis Pipeline {#yaf_sm_pipeline}
============================================

This tutorial is a step-by-step guide of setting up **yaf**, 
[super_mediator](http://tools.netsa.cert.org/super_mediator/index.html), and [Analysis Pipeline](http://tools.netsa.cert.org/analysis-pipeline5/index.html).

* [Overview](#overview)
* [Basic Install](#install)
* [Configure super_mediator](#sm)
* [Configure Analysis Pipeline](#pipeline)
* [Run YAF](#goyaf)
* [DNS Baselining with Pipeline](#analysis)

Overview {#overview}
==========

This tutorial explains the basics of setting up **yaf** to
**super_mediator** to **pipeline**.  It will also provide
the configuration to implement DNS Baselining, 
an idea presented at the 2017 FloCon.  The slides for the
presentation, titled "Low Hanging Fruit Tastes Just As Good",
can be found on the [FloCon web page](http://www.cert.org/flocon/index.cfm).

The idea behind DNS Baselining is if we create a list of all
the domains seen on the network for some period of time, and
if we're not already infected, malicious domains will be new
at some point.  Many attacks use recently registered domain names
and the change in domain resolutions can be potentially interesting.

**yaf** will be used to collect the DNS domain names.  
**super_mediator** will be used to de-duplicate the DNS domains 
and **pipeline** will be used to create the "whitelist" of 
DNS domains and then, after some period of time, will be used
to alert when new domains are seen.

Install prerequisites {#install}
========================
    $ yum groupinstall "Development Tools"
    $ yum install libpcap-devel pcre-devel
    
Build [libfixbuf](http://tools.netsa.cert.org/fixbuf/index.html):
    
    $ tar -xvzf libfixbuf-1.7.1.tar.gz
    $ cd libfixbuf-1.7.1
    $ ./configure
    $ make
    $ make install
    
Build **yaf**:
    
    $ tar -xvzf yaf-2.8.4.tar.gz
    $ cd yaf-2.8.4
    $ ./configure --enable-applabel --enable-plugins
    $ make
    $ make install
    
Build **super_mediator**:
    
    $ tar -xvzf super_mediator-1.5.0.tar.gz
    $ cd super_mediator-1.5.0
    $ ./configure
    $ make
    $ make install
    
Build [libschemaTools](http://tools.netsa.cert.org/schemaTools/download.html):
    
    $ tar -xvzf libschemaTools-1.2.1.tar.gz
    $ cd libschemaTools
    $ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
    $ ./configure
    $ make
    $ make install

Build [SiLK](http://tools.netsa.cert.org/silk/index.html):

    $ tar -xvzf silk-3.14.0.tar.gz
    $ cd silk-3.14.0
    $ ./configure --with-libfixbuf=/usr/local/lib/pkgconfig --enable-ipv6
    $ make
    $ make install

Build [pipeline](http://tools.netsa.cert.org/analysis-pipeline5/download.html)

    $ tar -xvzf	analysis-pipeline-5.6.tar.gz
    $ cd analysis-pipeline-5.6
    $ export LD_LIBRARY_PATH=/usr/local/lib
    $ ./configure --with-libsnarf=no --with-silk-config=/usr/local/bin/silk-config
    $ make
    $ make install
    
Setup super_mediator {#sm}
=====================

Create the file directories that **super_mediator** will use to write files
that **pipeline** will process:

    $ mkdir -p /data/pipeline/incoming/

Create your super_mediator.conf file.  One is installed by default into /usr/local/etc.  The following one will get you started:
    
    COLLECTOR TCP "yaf"
       PORT 18000
    COLLECTOR END
    
    #dedup process
    EXPORTER FILEHANDLER "dnsdedup"
       PATH "/data/pipeline/incoming/dns"
       REMOVE_EMPTY_FILES
       ROTATE 120
       DNS_DEDUP_ONLY
       LOCK
    EXPORTER END
    
    DNS_DEDUP "dnsdedup"
       RECORDS [1]
       MAX_HIT_COUNT 10000
       FLUSH_TIME 600
    DNS_DEDUP END
    
    LOGLEVEL DEBUG
    
    LOG "/var/log/super_mediator.log"
    
    PIDFILE "/data/super_mediator.pid"
    
Start **super_mediator**:

    $ super_mediator -c /usr/local/etc/super_mediator.conf --daemonize

Confirm **super_mediator** is running:

    $ ps -ef | grep super

If **super_mediator** is not running, check for any errors:

    $ cat /var/log/super_mediator.log

Configure Analysis Pipeline {#pipeline}
=========================    

The first step is to build the whitelist of domain names, 
domain/IP pairs, unique second-level domains (SLDs) and 
unique SLDs + top-level domains (TLDs).  The following 
**pipeline** configuration creates those 4 whitelists. 

    FILTER all
    END FILTER
    
    INTERNAL FILTER listBuilder
            FILTER all
            dnsQName sourceIPv4Address domainIPPairs 60 DAYS
            dnsQName domainList 60 DAYS
            DNS_SLD(dnsQName) slds 60 DAYS
            DNS_SLD+TLD(dnsQName) sldPlusTld 60 DAYS
    END INTERNAL FILTER
    
    LIST CONFIGURATION domainIPPairs
            UPDATE 5 MINUTES
            WRITE FILE WITHOUT ALERTING
            OUTPUT FILE "/data/pipeline/domainIPPairs.txt"
    END LIST CONFIGURATION
    
    LIST CONFIGURATION domainList
            UPDATE 5 MINUTES
            WRITE FILE WITHOUT ALERTING
            OUTPUT FILE "/data/pipeline/domainList.txt"
    END LIST CONFIGURATION
    
    LIST CONFIGURATION slds
            UPDATE 5 MINUTES
            WRITE FILE WITHOUT ALERTING
            OUTPUT FILE "/data/pipeline/slds.txt"
    END LIST CONFIGURATION
    
    LIST CONFIGURATION sldPlusTld
            UPDATE 5 MINUTES
            WRITE FILE WITHOUT ALERTING
            OUTPUT FILE "/data/pipeline/sldPlusTlds.txt"
    END LIST CONFIGURATION
    

Running **pipeline**:
    
    $ mkdir /data/pipeline/error

    /usr/local/sbin/pipeline  \
    --site-config-file=/data/silk.conf \
    --alert-log-file=/data/pipeline/alertLog.txt \
    --aux-alert-file=/data/pipeline/auxLog.txt \
    --ipfix \
    --time-field-name=flowStartMilliseconds \
    --configuration=/data/pipeline/whitelists.conf \
    --incoming-directory=/data/pipeline/incoming/ \
    --error-directory=/data/pipeline/error \
    --log-destination=syslog

Start YAF {#goyaf}
============

    $ mkdir /var/log/yaf

    $ export LTDL_LIBRARY_PATH=/usr/local/lib/yaf

Example **yaf** command line for sniffing interface eth0:
    
    /usr/local/bin/yaf
    --in eth0 --live pcap \
    --ipfix tcp \
    --out localhost \
    --log /var/log/yaf/yaf.log \
    --verbose \
    --silk \
    --verbose \
    --ipfix-port=18000 \
    --applabel --max-payload 2048 \
    --plugin-name=/usr/local/lib/yaf/dpacketplugin.so \
    --plugin-opts="53"


DNS Baselining with Pipeline {#analysis}
====================================

Once **pipeline** has been running for 4-6 weeks, sufficient
whitelists have been created and it is time to restart
**pipeline** with a configuration file that will use the 
whitelists to compare incoming domains against
and alert when new domains seen.  The whitelists will also be 
updated with the new domains so that **pipeline** only alerts
when a domain is seen for the first time ever or when it has not
been seen for over 60 days.

    FILTER newDomains
            dnsQName NOT IN LIST "/data/pipeline/domainList.txt"
            dnsQName NOT IN LIST newestDomains
    END FILTER
    
    INTERNAL FILTER newestDomains
            FILTER newDomains
            dnsQName newestDomains 60 DAYS
    END INTERNAL FILTER
    
    EVALUATION newDomains
            FILTER newDomains
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newDomainsOnlyFile
            dnsQName NOT IN LIST "/data/pipeline/domainList.txt"
    END FILTER
    
    EVALUATION newDomainsOnlyFile
            FILTER newDomainsOnlyFile
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newIPForDomains
            dnsQName IN LIST "/data/pipeline/domainList.txt"
            sourceIPv4Address dnsQName NOT IN LIST "/data/pipeline/domainIPPairs.txt"
            sourceIPv4Address dnsQName NOT IN LIST newestDomainIPPairs
    END FILTER
    
    INTERNAL FILTER newestDomainIPPairs
            FILTER newIPForDomains
            sourceIPv4Address dnsQName newestDomainIPPairs 60 DAYS
    END INTERNAL FILTER
    
    EVALUATION newIPForDomains
            FILTER newIPForDomains
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newIPForDomainsOnlyFile
            dnsQName IN LIST "/data/pipeline/domainList.txt"
            sourceIPv4Address dnsQName NOT IN LIST "/data/pipeline/domainIPPairs.txt"
    END FILTER
    
    EVALUATION newIPForDomainsOnlyFile
            FILTER newIPForDomainsOnlyFile
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newSlds
            DNS_SLD(dnsQName) NOT IN LIST "/data/pipeline/slds.txt"
            DNS_SLD(dnsQName) NOT IN LIST newestSlds
    END FILTER
    
    INTERNAL FILTER newestSlds
            FILTER newSlds
            DNS_SLD(dnsQName) newestSlds 60 DAYS
    END INTERNAL FILTER
    
    EVALUATION newSlds
            FILTER newSlds
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newSldsOnlyFile
            DNS_SLD(dnsQName) NOT IN LIST "/data/pipeline/slds.txt"
    END FILTER
    
    EVALUATION newSldsOnlyFile
            FILTER newSldsOnlyFile
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newSLDplusTLD
            DNS_SLD+TLD(dnsQName) NOT IN LIST "/data/pipeline/sldPlusTlds.txt"
            DNS_SLD+TLD(dnsQName) NOT IN LIST newestSLDplusTLD
    END FILTER
    
    INTERNAL FILTER newestSLDplusTLD
            FILTER newSLDplusTLD
            DNS_SLD+TLD(dnsQName) newestSLDplusTLD 60 DAYS
    END INTERNAL FILTER
    
    EVALUATION newSLDplusTLD
            FILTER newSLDplusTLD
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION
    
    FILTER newSLDplusTLDOnlyFile
            DNS_SLD+TLD(dnsQName) NOT IN LIST "/data/pipeline/sldPlusTlds.txt"
    END FILTER
    
    EVALUATION newSLDplusTLDOnlyFile
            FILTER newSLDplusTLD
            CHECK EVERYTHING PASSES
            END CHECK
            ALERT ALWAYS
            ALERT EVERYTHING
    END EVALUATION


Remove old alert files and restart **pipeline**:

    $ rm /data/pipeline/alertLog.txt
    $ rm /data/pipeline/auxLog.txt

    /usr/local/sbin/pipeline  \
    --site-config-file=/data/silk.conf \
    --alert-log-file=/data/pipeline/alertLog.txt \
    --aux-alert-file=/data/pipeline/auxLog.txt \
    --ipfix \
    --time-field-name=flowStartMilliseconds \
    --configuration=/data/pipeline/live_alert.conf \
    --incoming-directory=/data/pipeline/incoming/ \
    --error-directory=/data/pipeline/error \
    --log-destination=syslog


The data will look similar to:

    2017-01-31 20:19:16|Evaluation|newDomains|1|2016-12-01 00:01:01|216.239.34.102|1|ns-gce-public2.googledomains.com.|
    2017-01-31 20:19:16|Evaluation|newDomains|1|2016-12-01 00:01:01|216.239.38.102|1|ns-gce-public4.googledomains.com.|
    2017-01-31 20:19:16|Evaluation|newDomains|1|2016-12-01 00:01:01|216.239.36.102|1|ns-gce-public3.googledomains.com.|
    2017-01-31 20:19:16|Evaluation|newDomains|1|2016-12-01 00:01:01|216.239.32.102|1|ns-gce-public1.googledomains.com.|

**pipeline** will also allow you to filter out domains/SLDs/TLDs that are
not of interest to you.  That exercise will be left up to the reader.




    
