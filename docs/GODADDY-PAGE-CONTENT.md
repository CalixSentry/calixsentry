# CalixSentry install docs - ready to paste into GoDaddy Websites + Marketing

How to use this file:
1. In your GoDaddy site editor, create one PAGE per "== PAGE:" heading below.
2. Within each page, add a "Heading" section for each "###" line, and a "Text"
   section for the paragraphs under it.
3. Anything inside a fenced block (between the lines of dashes) is a COMMAND -
   put it in GoDaddy's "Code" section type if you have one, or a "Quote" block
   if not (both render in a fixed-width font, which is what matters here).
4. Do this once per page, click Preview, then Publish when it looks right.

--------------------------------------------------------------------------------
== PAGE: Overview / Install ==
--------------------------------------------------------------------------------

### Install CalixSentry

CalixSentry is a self-hosted, behavior-aware reverse-proxy firewall. It detects
automated scanning and OWASP-class web attacks, and ships in a mode that only
watches and records - it never blocks anything - until you decide otherwise.

### Requirements

Java 21 or newer. Nothing else - no database, no message queue, no separate
services to set up first.

### Choose your platform

Pick the page that matches where you're installing CalixSentry:
- Install on Linux (recommended for production)
- Install on macOS
- Install on Windows
- Install with Docker

Once it's running, see the Configuration & Verification page to point it at
your application and confirm it's working.

--------------------------------------------------------------------------------
== PAGE: Install on Linux ==
--------------------------------------------------------------------------------

### Install on Linux

Two ways to run CalixSentry on Linux: a quick one-shot run for trying it out,
or a permanent background service for production. Both use the same download.

### Step 1: Download and extract

--------------------------------------------
curl -LO https://download.calixsentry.com/v0.1.0/calixsentry-0.1.0-linux-x64.tar.gz
tar xzf calixsentry-0.1.0-linux-x64.tar.gz
cd calixsentry-0.1.0
--------------------------------------------

### Step 2a: Quick run (for trying it out)

Starts CalixSentry directly. It stops when you close the terminal.

--------------------------------------------
CALIXSENTRY_BACKEND_URL=http://localhost:3000 ./bin/calixsentry-engine
--------------------------------------------

### Step 2b: Production install (recommended)

Registers CalixSentry as a background service that survives reboots, generates
an admin password, and starts it in the safe default mode.

--------------------------------------------
sudo ./install.sh
--------------------------------------------

The installer checks that Java is installed, that the ports it needs are free,
and asks which application you want it to protect.

--------------------------------------------------------------------------------
== PAGE: Install on macOS ==
--------------------------------------------------------------------------------

### Install on macOS

Note: There is no native macOS installer yet. You run CalixSentry directly with
Java - it works the same as Linux, it just won't register itself as a
background service automatically.

### Step 1: Install Java 21 (if you don't already have it)

--------------------------------------------
brew install openjdk@21
--------------------------------------------

### Step 2: Download, extract, and run

--------------------------------------------
curl -LO https://download.calixsentry.com/v0.1.0/calixsentry-0.1.0.zip
unzip calixsentry-0.1.0.zip && cd calixsentry-0.1.0
CALIXSENTRY_BACKEND_URL=http://localhost:3000 ./bin/calixsentry-engine
--------------------------------------------

### Step 3: Keep it running (optional)

To keep CalixSentry running after you close the terminal, use a tool like
`tmux` or macOS's `launchd` - CalixSentry doesn't register itself as a
background service on macOS yet.

--------------------------------------------------------------------------------
== PAGE: Install on Windows ==
--------------------------------------------------------------------------------

### Install on Windows

Note: There is no native Windows installer yet. You run the same program
directly with Java. There's no Windows service wrapper, so use Task Scheduler
if you want it to survive a reboot.

### Step 1: Install Java 21

Download and install Java 21 from adoptium.net, then open PowerShell.

### Step 2: Download, extract, and run

--------------------------------------------
Invoke-WebRequest -Uri "https://download.calixsentry.com/v0.1.0/calixsentry-0.1.0.zip" -OutFile "calixsentry.zip"
Expand-Archive calixsentry.zip -DestinationPath .
cd calixsentry-0.1.0
$env:CALIXSENTRY_BACKEND_URL = "http://localhost:3000"
java -jar lib\calixsentry-engine.jar
--------------------------------------------

--------------------------------------------------------------------------------
== PAGE: Install with Docker ==
--------------------------------------------------------------------------------

### Install with Docker

### Step 1: Run the image, pointing it at your app

--------------------------------------------
docker run -d --name calixsentry \
  -p 8080:8080 -p 9400:9400 \
  -e CALIXSENTRY_BACKEND_URL=http://host.docker.internal:3000 \
  -e CALIXSENTRY_MANAGEMENT_BIND=0.0.0.0 \
  -v calixsentry-data:/data/calixsentry \
  calixsentry/calixsentry:latest
--------------------------------------------

### Step 2: Get your admin password

--------------------------------------------
docker exec calixsentry cat /data/calixsentry/initial-admin-password.txt
--------------------------------------------

--------------------------------------------------------------------------------
== PAGE: Configuration & Verification ==
--------------------------------------------------------------------------------

### Point CalixSentry at your application

One setting decides what CalixSentry protects - where it forwards traffic once
a request has been inspected and allowed through. Set it via the
CALIXSENTRY_BACKEND_URL environment variable:

Same machine:
--------------------------------------------
CALIXSENTRY_BACKEND_URL=http://localhost:3000
--------------------------------------------

Another server, by IP address:
--------------------------------------------
CALIXSENTRY_BACKEND_URL=http://10.20.30.40:8080
--------------------------------------------

An internal hostname:
--------------------------------------------
CALIXSENTRY_BACKEND_URL=http://app.internal.mycompany.com:8080
--------------------------------------------

A cloud-hosted origin:
--------------------------------------------
CALIXSENTRY_BACKEND_URL=https://origin.example.com
--------------------------------------------

### Verify it's running

CalixSentry uses two separate ports on purpose: the gateway (port 8080) is
what your visitors hit; the dashboard (port 9400) stays off that port
entirely, so it's simply not there for the internet to find.

Check the gateway is healthy:
--------------------------------------------
curl -i http://localhost:8080/health
--------------------------------------------

Then open the dashboard in your browser at:
http://localhost:9400/calixsentry/

Log in as "admin" with the password that was printed to the console the
first time CalixSentry started.

### It starts in MONITOR mode

Every request is inspected and scored, but nothing is ever blocked, until you
switch modes yourself from the dashboard. This is the safe default.

### Platform support, honestly

- Linux (background service): fully automated
- Linux (quick run) / Docker: fully automated
- macOS / Windows: you run it manually with Java - no installer yet
- apt / yum package installs: not available yet
- Automatic updates: not available yet
