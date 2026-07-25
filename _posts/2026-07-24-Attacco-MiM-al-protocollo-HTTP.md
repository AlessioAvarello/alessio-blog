---
layout: article
title: "Attacco MiM al protocollo HTTP"
date: 2026-07-24
tags: [Attacchi]
---
# Attacco tramite MiM al protocollo HTTP

Questo articolo ha come fine quello di dimostrare le vulnerabilità dei protocolli che trasmettono dati in chiaro. L’attaccante si posiziona come Man in The Middle strategicamente fra il server host e il dispositivo della vittima. Tramite l’ARP Poisoning, l’attaccante riesce a deviare il normale flusso di traffico, facendo transitare i dati prima verso la sua macchina e poi verso il server. Deviato il flusso, è molto semplice per un attaccante violare confidenzialità, integrità, autenticazione e non ripudio. Questo attacco sfrutterà tre diversi endpoint: 

- **Endpoint Server**: Un server creato tramite Python e Flask. Questo hosterà un sito web in locale e renderizzerà una semplice interfaccia di login.
- **Endpoint Vittima**: Deve essere un qualsiasi dispositivo connesso alla rete LAN, e deve possedere un browser in grado di connettersi all’IP del server.
- **Endpoint Attaccante**: L’attaccante sfrutterà i tool preinstallati in Kali Linux, come Ettercap e Wireshark per posizionarsi in mezzo fra server e vittima.

### 1. Il server locale

Lo script di backend definisce l’architettura logica del server target. Sviluppato tramite Python, il software sfrutta Flask per istanziare un socket in ascolto e gestire metodi di richiesta **GET** (deputato all’invio dell’interfaccia grafica del form) e **POST** (utilizzato per la ricezione e l’elaborazione dei dati inseriti dall’utente). Di default, un’applicazione Flask
si pone in ascolto esclusivamente sull’interfaccia locale (127.0.0.1), limitando la
connettività all’host interno. Questa configurazione associa il server a tutte le interfacce di rete attive, proiettando il servizio sulla porta TCP 5000 e rendendolo accessibile da qualsiasi endpoint associato alla LAN fisica tramite digitazione dell’indirizzo IP locale dell’host. Per l’interazione con l’utente, lo script esegue il rendering del file login.html, posizionato nella cartella templates. L’elemento cardine della struttura e identificato dal tag **form method=”POST**”. Questa
istruzione impone al browser di incapsulare i parametri inseriti nei campi di input username e password, direttamente all’interno del payload della richiesta HTTP POST non appena viene rilevato l’evento di submit.

### 2. Deviazione del traffico tramite ARP Poisoning

L’obiettivo dell’attaccante `e forzare il transito dei pacchetti attraverso la macchina
Kali Linux. Questa sottomissione logica viene eseguita tramite la tecnica dell’**ARP
Poisoning**. 

1. Dal terminale di Kali Linux viene invocata l’interfaccia grafica del tool di
rete Ettercap tramite il comando `sudo ettercap -G`.
2. Viene eseguita una scansione dei dispositivi attivi all’interno della LAN
per isolare gli indirizzi IP dei bersagli.
3. All’interno del pannello di controllo Ettercap, viene configurato l’indirizzo IP del server Flask come Target 1 e l’indirizzo IP della vittima come Target 2.
4. Viene avviata la routine di ARP Poisoning abilitando l’opzione Sniff Remote Connections. Da questo istante, Ettercap invia pacchetti ARP gratuitous falsificati. Il client viene indotto a mappare l’IP del server sul MAC Address di Kali, e il server mappa l’IP del client sul medesimo indirizzo MAC dell’attaccante, stabilendo un canale Man-in-the-Middle.

### 3. Intercettazione del Payload

Una volta deviato il percorso di routing, sulla macchina Linux viene avviato
l’analizzatore di protocollo Wireshark (sudo wireshark). La cattura dei pacchetti viene eseguita sull’interfaccia di rete logica eth0. Per scartare i pacchetti
non rilevanti e rimuovere il rumore di fondo della rete locale, viene applicato
un filtro di visualizzazione: http.request.method == "POST". Al momento
dell’autenticazione della vittima, Wireshark intercetta in tempo reale il segmento TCP contenente la richiesta di POST. All’interno della sezione HTML
Form URL Encoded, vengono estratte in chiaro le credenziali digitate precedentemente dalla vittima.

![Payload intercettato dall'attaccante]({{ site.baseurl }}/assets/articolo1/credenzialihttp.png)

### 4. Proprietà di Sicurezza Violate

In questo scenario con HTTP in chiaro, l’assenza di qualsiasi forma di crittografia determina l’annullamento di varie proprietà di sicurezza: 

- **Confidenzialità**: Viene violata in modo passivo e non rilevabile. Il payload transita come testo semplice e quindi l’intercettazione dei pacchetti tramite Wireshark espone istantaneamente username e password.
- **Integrità**: L’attaccante MitM potrebbe intercettare la richiesta POST
per poi modificarne arbitrariamente i dati e inoltrarla al server, il quale la
accetterà come valida poiché non possiede alcun strumento per verificare
l’alterazione.
- **Autenticazione e Non Ripudio**: Chiunque potrebbe iniettare pacchetti spacciandosi per la vittima, invalidando la paternità dei flussi e facendo cadere il Non Ripudio. Inoltre la connessione è basata solamente sull’indirizzo IP, e questo priva il client di garanzie sulla reale identità del
server.
- **Disponibilità**: Il controllo del routing permette all’attaccante di eseguire
pacchetti di DoS, forzando il timeout della sessione del client.

### 5. Mitigazione

La mitigazione diretta contro questo scenario è l’header **HSTS (HTTP Strict Transport Security)**. Questo header raccomanda al browser di non effettuare mai un downgrade da HTTPS ad HTTP, riscrivendo ogni richiesta in HTTPS prima che parta sulla rete. Questo neutralizza gli attacchi come SSL Strip, e impedirebbe ad un attaccante di visualizzare il payload in chiaro con ARP Poisoning. 

Questo header presuppone ovviamente che TLS sia già configurato correttamente, la versione minima accettabile deve essere TLS 1.2 e non si devono utilizzare mai versione di TLS precedenti. 

Anche HTTPS deve essere configurato correttamente, impostando cipher suite robuste con forward secrecy (ECDHE) e certificati validi con corretta catena di trust.