include('spfCheck.php')

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
