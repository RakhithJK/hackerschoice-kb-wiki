<h1>LSDR - Linux and Software Defined Radio 101</h1>

<h2>0x00 Preface</h2>

Having started my journey w/ Linux and SDR in 2012, back then I had to manually compile lots of stuff, sometimes including a dependency hell. Still, there was already alot going on - a growing codebase from the [GNU Radio project](https://en.wikipedia.org/wiki/GNU_Radio) combined w/ [OsmoCom](https://osmocom.org/) code and a cheap and easily affordable Realtek chipset based DVB-T receiver already opened up a whole world of possibilities. I later on bought a [HackRF One](https://en.wikipedia.org/wiki/HackRF_One) and there also was the [rad1o badge](https://rad1o.badge.events.ccc.de/) from the german hacker camp in 2015, both offering a even broader frequency range of up to 4 or 6 GHz as well as transceiver capabilities.


<h2>0x01 H/W</h2>

I recently got ahold of [NESDR SMArTee v2](https://www.nooelec.com/store/sdr/sdr-receivers/nesdr-smartee-sdr.html) and [NESDR SMArT XDR](https://www.nooelec.com/store/sdr/sdr-receivers/nesdr-smart-xtr-sdr.html) receivers at a friendly [hackerspace](https://en.wikipedia.org/wiki/Hackerspace) and wanted to dive a little bit deeper into the world of radiowave reconnaissance. Both devices have a RTL2832U Demodulator/USB interface IC, the v2 has a R820T2 tuner and the XDR a E4000 tuner. They are also physically designed to fit side by side in a [RPi](https://en.wikipedia.org/wiki/Raspberry_Pi) device that might be nice to place e.g. in the attic or at some other remote location. In general, you can just look for "RTL SDR" at your favorite shopping site and you will find lots of cheap alternatives to the H/W mentioned above.


<h2>0x02 S/W</h2>

Running [Debian GNU/Linux](https://en.wikipedia.org/wiki/Debian) on nearly all of my computational devices, I started from scratch to setup the S/W and tools required to actually use the RTL-SDR devices, which turned out to be as simple as never before. Basically, all I had to do was installing a few required packages along w/ their automatic dependencies via apt:

<code>sudo apt install gqrx-sdr multimon-ng sox rtl-433 cubicsdr librtlsdr-dev opencpn -y</code>

as well as some more specific tools via python pip:

<code>pip install --user pyModeS pyrtlsdr</code>

and via git:

<code>git clone https://github.com/TLeconte/acarsdec.git</code> (for [ACARS](https://en.wikipedia.org/wiki/ACARS))</code>

<code>git clone https://github.com/jvde-github/AIS-catcher.git</code> (for [AIS](https://en.wikipedia.org/wiki/Aeronautical_Information_Service))</code>


<h2>0x03 POCSAG

After having built and/or installed all required S/W, recon got started by firing up <code>gqrx</code> on the lookout for data transmitted over the air, and the first thing I stumbled upon was a periodical broadcast of data that distantly remembered me of the old modem era, and which - after some research - turned out to be one or another form of [POCSAG](https://en.wikipedia.org/wiki/Radio-paging_code_No._1). This protocol is basically used for text paging (yes, skyper xD) all around the globe and wikipedia gives you a quite lengthy list of actual frequencies to play with.

To be able to decode the messages into their (alpha-)numeric format, we already installed [multimon-ng](https://github.com/EliasOenal/multimon-ng) and could now pipe the data from gqrx (after having clicked on UDP in the receiver options tab) directly into sox (to convert the raw audio to multimon-ng's native raw format) and then into multimon-ng:

<code>nc -l -u localhost 7355 | sox -t raw -esigned-integer -b 16 -r 48000 - -esigned-integer -b 16 -r 22050 -t raw - | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -p --timestamp - </code>

The output might look something like this:

<code>2022-09-08 17:41:49: POCSAG1200: Address:   xxxxx  Function: 3  Alpha:   A: 08.09.22 17:27:18 B165 Anckelmannsplatz NSK (20m) Pegel L089-5.00 mNN Erreicht<EOT> </code>

The data comes in at bursts every few seconds and includes lots of different information which might be the wet dream of passive information gathering affected hackers.


<h2>0x04 FMS FSK</h2>

Reading the man page, multimon-ng decodes a bunch of different other radio transmissions, so it might make sense to add more demodulators to be able to spot them in the overwhelming amount of broadcasted data. One of these is FMS which seems to be used to transmit at least some elements of the status of police, ambulance or even governmental agencies (BGS, BKA) cars either going to, arriving at or coming from their place of action. Output received might look like:

<code>2022-09-08 18:04:49: FMS: xxxxxxxxxxxx (d=Rettungsdienst        a=Rheinland-Pfalz       Ort xxxx=xxx    FZG xxxx        Status 2=Einrucken/Abbr 1=LST->FZG      0=I  (ohneNA,ohneSIGNAL)        ) CRC INCORRECT (22)
</code>

and seems to also include the state of the car's blue rooftop light and/or siren, which might serve as a form of protocol for their control station as well.


<h2>0x05 POCSAG/FMS Recap</h2>

Collecting the POCSAG and FMS data over a period of time gives you a nice base for correlation and more recon, e.g. by looking up parts of the messages, certain terms used in them and by checking out different frequencies which might contain a different spectrum of message types. What I saw so far are not only the mentioned messages, but also:

* data from server monitoring
* information about incoming tickets and/or e-mail
* license plate readers at big companie's truck gates
* stock market trading
* uninterruptible power supplies
* detailed messages of ambulance dispatches
* burglary alarms 

to name only a few. We also see certain, similar messages either coming from the same POCSAG address or an apparent group of neighboured addresses and are easily able to grep for certain content or addresses as a first step of sorting and inspection. At this point, we can also be pretty sure that we are able to listen to nationwide text paging messages.


<h2>0x06 ADS-B</h2>

Being curious about what else might be out there, I continued to inspect [ADS-B](https://en.wikipedia.org/wiki/Automatic_Dependent_Surveillance%E2%80%93Broadcast) to see if I would be able to receive information similar to the one presented at sites like https://flightradar24.com. ADS-B globally operates mostly at a predefined frequency of 1090MHz. Again, we split the process of displaying relevant data into

* setting the tuner, receiving and collecting the data
* export/pipe that into a sort of decoder

which is why I wrote two skripts:

<code>ADS-B_cap.sh: rtl_adsb | nc -klnvp 8080</code>

This tunes to 1090MHz and exports received data to a netcat listener on port 8080, whereas

<code>ADS-B_view.sh: modeslive --source net --connect localhost 8080 raw</code>

connects to that netcat listener and decodes the data using the <code>modeslive</code> command that we installed via pyModeS earlier.

Output might look similar to:

<code>3c5eec  EWG9726_  50.29134   2.84372         444                    1088    148.06</code>

and mostly includes the callsign, GPS positions, groundspeed and so on. There are tons of articles on the internet on how to further visualize such data on a map, looking up the callsigns in a database of actual airplanes etc. which is exactly what sites like flightradar24 do. You can even easily export your own data to their servers to help in painting a more complete overall picture.


<h2>0x07 AIS</h2>

Living close to a river, I decided to checkout if those ships also emit data, and guess what, their system is called [Aeronautical Information Service (AIS)](https://en.wikipedia.org/wiki/Aeronautical_Information_Service) and thanks to more FOSS, we are of course able to receive and decode this as well. This time, we use a standalone binary we installed via git and call it via another script:

<code>AIS.sh: AIS-catcher -u 127.0.0.1 10101 | tee -a AIS.LOG</code>

Output might look like

<code>!AIVDM,2,1,0,A,539dbM400000@K?O3@1=@4AB0PDTh98tpp00000D1@111t000030EAQQ,0*3C ( MSG: 5, REPEAT: 0, MMSI: 211495540)</code>

By using the <code>-u</code> switch, we again open up a UDP service from which we can export collected data to some form of frontend like [OpenCPN](https://www.opencpn.org/) which plots the found vessels on a map and offers a target query which includes 

* the ship's name
* its length
* cargo
* GPS position
* destination
* ETA at destination

AIS seems to have a radius of about 75km and has a rather weak signal strength, but I can imagine that close to the sea you might get some quite interesting results. _(Note: Some years ago, rumors spread that somalian pirates were able to choose the vessel based on its cargo, which might be not that far fetched.)_


<h2>0x08 Sensor Data (SRD/ISM) </h2>

The next thing that I was interested in were all these weather stations and their sensor data, and sure enough, we got everything we need already installed. 

Some of the [ISM bands](https://en.wikipedia.org/wiki/ISM_radio_band) are located at 433.92MHz, 868MHz ([SRD](https://en.wikipedia.org/wiki/Short-range_device#SRD860)), 315MHz and 915MHz.

Instead of checking weather sites or checking my own analogue or digital thermometer, I could simply receive that informations from some random weather station of another house in proximity:

<code>cat SENSOR_868.sh: rtl_433 -f 868M -s 1024k</code>

resulting in output like:

<code>Battery   : 1            Temperature: 16.7 C       Humidity  : 90 %          Wind direction: 14        Wind speed: 0.0 m/s       Gust speed: 0.0 m/s       Rainfall  : 799.8 mm      UV        : 18            UVI       : 0             Light     : 1968.0 lux</code>

There are tons of other device decoding protocols implemented of which already most are loaded by default after startup:

<code>Registered 145 out of 175 device decoding protocols [ 1-4 8 11-12 15-17 19-21 23 25-26 29-36 38-60 63 67-71 73-100 102-105 108-116 119 121 124-128 130-149 151-161 163-168 170-175 ]</code>

and which might make it very interesting to scan other frequency ranges for such data as well as do some sort of wardriving.


<h2>0x09 Advanced Recon</h2>

When running <code>gqrx</code>, it becomes pretty clear that it can only show you a small portion of the radio spectrum, which is perfectly good if you know what you are looking for in a sort of "live" setup. However, if we want to observe a broader area and at the same time cover a greater time period, then we can use the very handy [rtl_power](http://kmkeen.com/rtl-power/) utility. I recommend to write different scripts for different purposes, e.g.

<code>RTLPOWER_AIRBAND.sh: rtl_power -f 118M:137M:8k -g 50 -i 10 -e 1h airband.csv</code>

which will monitor the whole [airband](https://en.wikipedia.org/wiki/Airband) spectrum in 8KHz steps and save the data every 10 seconds in a CSV file over a period of one hour. To visualize that data, the [heatmap.py](https://github.com/keenerd/rtl-sdr-misc/blob/master/heatmap/heatmap.py) utility comes into play which we can use in a script like

<code>BUILDMAP.sh: python3 heatmap.py $1.csv $1.png ; display $1.png</code>

to generate a very nice image together w/ a nice scale to identify where transmissions take place.

In the airband case, you will see active radio transmissions by the pilots as bright dots, and this might greatly help you in spotting the active frequencies in your area, which you can then survey live and listen in using [NFM](https://en.wikipedia.org/wiki/Frequency_modulation#narrowband_FM) modulation.

In the case of POCSAG, the periodically occuring transmits create nice dashed lines which are - depending on the signal strength - also very easy to spot in the resulting image.


<h2>0x0A References</h2>

* https://www.gnuradio.org/
* https://osmocom.org/projects/rtl-sdr/wiki
* https://gqrx.dk/
* https://github.com/EliasOenal/multimon-ng
* http://sox.sourceforge.net/
* https://github.com/junzis/pyModes
* https://github.com/merbanan/rtl_433
* https://github.com/cjcliffe/CubicSDR
* https://github.com/librtlsdr/librtlsdr
* https://www.opencpn.org/
* https://www.rtl-sdr.com/


<h2>0x0B Epilogue</h2>

To learn about the things documented here, I used my SDR receivers for ~ 2 weeks besides my normal work. I assume that I will extend and update this knowledge base over time as I consider the whole project work-in-progress. 

Shoutz to Skyper/THC for creating this wiki besides having written and still writing great pieces of S/W, the 1nf1n1te v01d crew and Phenoelit (ph-neutral rocked!). It is nice to see a great community of free and open source software developers and hackers spread but still co-working all over the world and participating in global online-events like the [rc3](https://media.ccc.de/b/conferences/rc3).