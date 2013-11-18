<?php

/*
 * Class spfCheck
 * Accepts a Domain Name as input and checks for a valid SPF record
 * Can also check for the presence of a given string.
 *
 * @author RazidAhmad
 */
class spfCheck {
    
    protected $domain = null;      //domain name to be checked
    protected $txtRecord = null;   //used to store txt record obtained from domain
    protected $spfRecord = null;   //used to store the single SPF record, if present
    protected $txtString = null;   //used to store desired string in SPF record
    protected $numLookups = 0;
    
    /*
     * Creates class
     * 
     * @param $domain = fully qualified domain name to be checked
     * @param $txtString = string that is expected to be in SPF record
     * @param $numLookups = should be zero on initial call
     */
    public function __construct($domain, $txtString, $numLookups){
        //Initialize class properties with constructor values
        $this->domain = $domain;
        $this->txtRecord = dns_get_record($this->domain, DNS_TXT);
        $this->txtString = $txtString;
        $this->numLookups = $numLookups;
    }
    
    public function getTxtRecord(){
        return $this->txtRecord;
    }
    
    public function getSpfRecord(){
        if ($this->spfRecord == null)
            $this->hasSingleSPFRecord();
        return $this->spfRecord;
    }
    
    public function getDomain(){
        return $this->domain;
    }
    
    public function getTxtString(){
        return $this->txtString;
    }
    
    //Tests to see if $this->domain has a single SPF record
    public function hasSingleSPFRecord(){
        $spfFound = 0;
        $numRecords = count($this->txtRecord);
        for ($i = 0; $i < $numRecords; $i++){
            if (stripos($this->txtRecord[$i][txt], "v=spf1 ") === 0){
                $spfFound++;
                $this->spfRecord = $this->txtRecord[$i][txt];
            }
        }
        if ($spfFound == 0){
            //echo "ERROR:  No SPF Record Found<br>";
            return FALSE;
        }elseif ($spfFound > 1){
            //echo "ERROR:  More than one SPF record found<br>";
            $this->spfRecord = null;
            return FALSE;
        }elseif ($spfFound == 1)
            return TRUE;
    }
    
    //Tests to see if the singls SPF record found by hasSingleSPFRecord() ends with
    //~all or -all and whether "all" occurrs only at the end.
    public function endsWithAll(){
        if ((strripos($this->spfRecord, " ~all") === stripos($this->spfRecord, " ~all")) &&
                (stripos($this->spfRecord, " ~all") !== FALSE) &&
                (strripos($this->spfRecord, "all") ===  stripos($this->spfRecord, "all"))){
            //echo "SUCCESS:  SPF record terminates with ~all<br>";
            return TRUE;
        }else{
            //echo "ERROR:  SPF record does not terminate with ~all, or all is used more than once.<br>";
            return FALSE;
        }
    }
    
    public function hasTxtString(){
        if (stripos($this->spfRecord, $this->txtString) !== FALSE){
            //echo "SUCCESS:  SPF record contains $this->txtString<br>";
            return TRUE;
        }else {
            //echo "ERROR:  SPF record does not contain $this->txtString<br>";
            return FALSE;
        }
    }
    
    public function countLookups(){
        if (($this->hasSingleSPFRecord()) && ($this->numLookups < 10)){
            $parsedSPF = explode(" ", $this->spfRecord);
            $i=0;
            while (($i < count($parsedSPF)) && ($this->numLookups < 10)){
                if (stripos($parsedSPF[$i], "a") === 0 )
                        $this->numLookups = $this->numLookups + 1;
                if (stripos($parsedSPF[$i], "exists") === 0 )
                        $this->numLookups = $this->numLookups + 1;
                if (stripos($parsedSPF[$i], "ptr") === 0)
                        $this->numLookups = $this->numLookups + 2;
                if (stripos($parsedSPF[$i], "mx") === 0)
                        if (stripos($parsedSPF[$i], "mx:") === 0){
                            $this->numLookups = $this->numLookups + 1 + count(dns_get_record(substr($parsedSPF[$i], 3), DNS_MX));
                        }else
                            $this->numLookups = $this->numLookups + 1 + count(dns_get_record($this->domain, DNS_MX));
                if ((stripos($parsedSPF[$i], "include:") === 0) && ($this->numLookups < 10)){
                        $newDomain = substr($parsedSPF[$i], 8);
                        //echo "$newDomain <br>";
                        $newSpfCheck = new spfCheck($newDomain, " ", $this->numLookups);
                        $this->numLookups = 1 + $newSpfCheck->countLookups();
                }
                $i++;
            }           
        }
        return $this->numLookups;
    }
}

// basic testing script for spfCheck class

$newCheck = new spfCheck(htmlspecialchars($_GET["domain"]), "include:aspmx.pardot.com", 0);

$currentDomain = $newCheck->getDomain();
$txtRecords = $newCheck->getTxtRecord();
$txtString = $newCheck->getTxtString();
$spfRecord = $newCheck->getSpfRecord();

$numRecords = count($txtRecords);

echo "$numRecords TXT record(s) found for $currentDomain<br>";
for ($i = 0; $i < $numRecords; $i++)
    printf("&nbsp&nbsp&nbsp%s <br>", $txtRecords[$i][txt]);
echo "<br>";

if ($newCheck->hasSingleSPFRecord())
    echo "Success:  A single SPF record was found: \"$spfRecord\" <br>";
else 
    echo "Error:  No SPF record found or multiple SPF records found <br>";

if ($newCheck->endsWithAll())
    echo "Success:  SPF record ends with ~all <br>";
 else 
     echo "Error:  SPF record does not end with ~all or all is used more than once<br>";

if ($newCheck->hasTxtString())
    echo "Success:  SPF record contains $txtString <br>";
else
    echo "Error:  SPF record does not contain $txtString <br>";

$numLookups = $newCheck->countLookups();
if ($numLookups <= 10)
    echo "Success:  SPF record uses $numLookups DNS lookups <br>";
else
    echo "Error:  SPF record uses $numLookups or more DNS lookups.  The limit is 10 <br>";


?>
