---
layout: article
title: "TLS Downgrade verso protocollo HTTPS Insicuro"
date: 2026-07-25
tags: [Attacchi]
---

Mostrare le vulnerabilità dei protocolli che inviano messaggi in chiaro è stato semplice e banale. Con questo articolo voglio dimostrare che anche con l’aggiunta di HTTPS, le comunicazioni possono essere insicure. Infatti, se HTTPS non è implementato correttamente, l’attaccante può sfruttare metodi come il TLS Downgrade o SSL Strip a suo vantaggio per violare la confidenzialità e l’integrità delle comunicazioni. Se l'infrastruttura fa uso di certificati auto-firmati, suite di cifratura obsolete e versioni del protocollo deprecate, il sistema di difesa cade. La presenza dell'icona del lucchetto, che rappresenta il canale sicuro all'interno della barra degli indirizzi del browser, si può tradurre in una falsa percezione della sicurezza.

### 1. Generazioni del Certificato e delle Chiavi Crittografiche

Prima di procedere alla configurazione del server Flask, è stato necessario generare una coppia di chiavi crittografiche asimmetriche. Utilizzando le utility fornite dalla suite OpenSSL, è stato eseguito il seguente comando di inizializzazione: 

```shell
openssl req -x509 -newkey rsa:2048 -nodes -out cert.pem -keyout key.pem -days 365
```

Questo comando genera un certificato conforme allo standard X.509 auto-firmato. Istanzia una chiave privata basata sull'algoritmo asimmetrico RSA con una lunghezza di cifra pari a 2048 bit, garantendo una robustezza standard. Per consentire al server di accedere automaticamente alla chiave, il comando ne rimuove la passphrase locale, così che questa possa essere caricata in memoria in modo automatizzato.

### 2. Implementazione del Redirect

Per replicare l'architettura dei browser moderni, che hanno un sistema di reindirizzamento automatico al protocollo sicuro, lo script Python è stato modificato introducendo il **multithreading**. Adesso il server Flask gestisce contemporaneamente due istanze applicative associate a socket differenti: 

- **Istanza 5000**: Avvia il protocollo HTTP, il cui scopo è intercettare le richieste iniziali del client e rispondere con un codice di stato **301 Moved Permanently**, rendirizzando l'utente verso l'endpoint sicuro. Questo reindirizzamento rappresenta il punto critico della vulnerabilità, in quanto la prima richiesta avviene interamente in chiaro.
- **Istanza 5443**: Avvia il protocollo HTTPS, con contesto crittografico volutamente indebolito forzando l'utilizzo della suite crittograffica **AES128-SHA** e dello standard **TLS 1.2**. Questa suite crittografica infatti, utilizza SHA-1 per la verifica dell'integrità, esponendo il canale a vulnerabilità note per collisioni hash

```python
import ssl
import threading
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

DEMO_USER = "admin"
DEMO_PASS = "password123"

SECURE_MODE = False
ENABLE_HSTS = False

# SECURE_MODE = True  → TLS 1.3 only        
# ENABLE_HSTS = True  → header HSTS attivo    

@app.route('/', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == DEMO_USER and password == DEMO_PASS:
            message = "Login effettuato con successo! Benvenuto in area sicura."
        else:
            message = "Credenziali errate. Riprova."
    return render_template('login.html', message=message)

@app.after_request
def add_security_headers(response):
    if ENABLE_HSTS:
        response.headers['Strict-Transport-Security'] = \
            'max-age=31536000; includeSubDomains; preload'
    return response

redirect_app = Flask(__name__ + "_redirect")

@redirect_app.route('/', defaults={'path': ''})
@redirect_app.route('/<path:path>')
def redirect_to_https(path):
    host = request.host.replace(':5000', ':5443')
    return redirect(f'https://{host}/{path}', code=301)

def run_https():
    if SECURE_MODE:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        print("[HTTPS] Modalità SICURA  — TLS 1.3 obbligatorio")
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers('AES128-SHA')
        print("[HTTPS] Modalità VULNERABILE — TLS 1.2 + AES128-SHA (no PFS)")

    context.load_cert_chain('cert.pem', 'key.pem')
    print(f"[HTTPS] HSTS    : {'ABILITATO' if ENABLE_HSTS else 'DISABILITATO'}")
    print(f"[HTTPS] Expect-CT: {'ABILITATO' if ENABLE_HSTS else 'DISABILITATO'}")
    print("[HTTPS] Server avviato su https://0.0.0.0:5443")
    app.run(host='0.0.0.0', port=5443, ssl_context=context,
            debug=False, use_reloader=False)

def run_http():
    print("[HTTP]  Redirect -> https://...:5443 (punto vulnerabile)")
    redirect_app.run(host='0.0.0.0', port=5000,
                     debug=False, use_reloader=False)

if __name__ == '__main__':
    t_http  = threading.Thread(target=run_http,  daemon=True)
    t_https = threading.Thread(target=run_https, daemon=True)

    t_http.start()
    t_https.start()

    tls_mode = "1.3 — sicuro (mitigazione)" if SECURE_MODE \
               else "1.2 + AES128-SHA — vulnerabile (no PFS)"

    print(f"  HTTP  (redirect)  : http://localhost:5000")
    print(f"  HTTPS (target)    : https://localhost:5443")
    print(f"  TLS               : {tls_mode}")
    print(f"  HSTS              : {'ON  — mitigazione' if ENABLE_HSTS else 'OFF — vulnerabile'}")
    print("="*52)
    print(f"  [FLAGS] SECURE_MODE={SECURE_MODE}  ENABLE_HSTS={ENABLE_HSTS}")
    print("="*52)
    print("  Ctrl+C per fermare\n")

    try:
        t_http.join()
        t_https.join()
    except KeyboardInterrupt:
        print("\n[INFO] Server fermati.")
```

### 3. Warning di Sicurezza del Browser

All'avvio del server tramite prompt dei comandi, il tentativo di connessione della vittima all'URL verrà fermato da un warning del browser, il quale visualizza un codice di errore **ERR_CERT_AUTHORITY_INVALID**. Questo accade perché ogni browser integra un archivio di CA fidate (Root Trust Store) e il certificato presentato dal server Flask viene rifiutato poiché l'emittente coincide con il soggetto stesso, rendendo impossibile verificare la catena di fiducia (Chain of Trust). La vittima sceglie di bypassare l'avviso cliccando su "Procedi su host (non sicuro)", stabilendo così una sessione che usa una versione TLS debole. 

![Warning del server]({{ site.baseurl }}/assets/articolo2/warning.png)

### 4. Diagnostica del Server e TLS Downgrade

L'attaccante adesso esegue un'attività di ricognizione dalla macchina Kali Linux per scoprire le suite crittografiche e le versioni del protocollo accettate dal server target. Sfruttando la diagnostica inclusa in OpenSSL, viene invocato il comando per forzare un handshake crittografico completo esplicitando il parametro di sottomissione del protocollo: 

```bash
openssl s_client -connect 192.168.0.100:5443 -tls1_2
```

L'aggiunta del flag **tls1_2** al termine del comando è fondamentale, in questo modo il client tenta intenzionalmente di forzare un **TLS Downgrade**, richiedendo al server di negoziare la sessione tramite uno standard vecchio e deprecato anziché avvalersi di versioni più moderne e sicure. I log di risposta estratti dal terminale confermano che il server accetta connessioni di questo tipo evidenziano due criticità severe: 

- **Vulnerabilità per collisione**: L'algoritmo SHA-1 non è più considerato sicuro, perché è matematicamente possibile che due input differenti generino la medesima stringa di output, compromettendo l'integrità.
- **Assenza di Perfect Forward Secrecy (PFS)**: Lo scambio delle chiavi simmetriche di sessione avviene tramite crittografia RSA statica classica. Non è quindi presente nessun meccanismo di scambio chiavi effimero (come DH), questo permetterebbe a un attaccante di registrare passivamente il traffico di rete e se in futuro riuscisse a compromettere la chiave privata del server, sarebbe in grado di decifrare retroattivamente tutti i dati intercettati nel passato.

![Protocolli e Cipher suite usate dal server]({{ site.baseurl }}/assets/articolo2/serverstats.png)

### 5. Proprietà di Sicurezza Violate

L'introduzione di HTTPS in un contesto TLS 1.2 e un certificato auto-firmato modifica la natura del rischio. In questa dimostrazione l'attaccante non riesce più a leggere direttamente i dati in transito, ma alcune proprietà di sicurezza potrebbero essere comunque violate: 

- **Confidenzialità ed Esposizione Retroattiva**: La suitLa suite basata sullo scambio di chiavi RSA statico è un problema per la riservatezza a lungo termine. Se la chiave privata venisse ottenuta da un attaccante, questo potrebbe decifrare retroattivamente l'intera cronologia dei dati passati. e basata sullo scambio di chiavi RSA statico è un problema per la riservatezza a lungo termine. Se la chiave privata venisse ottenuta da un attaccante, questo potrebbe decifrare retroattivamente l'intera cronologia dei dati passati.
- **Integrità**: L'algoritmo di hashing SHA-1 per la verifica dell'integrità espone il canale ad attacchi basasti su collisione crittografica.
- **Autenticazione**: L'uso di un certificato self-signed spezza la catena di fiducia. Nonostante il browser segnali l'anomalia, l'abitudine della vittima a bypassare il warning azzera l'efficacia dell'autenticazione. L'utente perde la capacità di distinguere il server legittimo da un'interfaccia fittizia generata da un attaccante.
- **Esposizione al Downgrade**: L'assenza dell'header HSTS in quante fase permetterebbe a un attaccante posizionato come MitM di intercettare la prima richiesta in chiaro e bloccare la transizione verso HTTPS, facendo comunicare la vittima con un canale non protetto.

### 6. Strategie di Mitigazione

Dobbiamo quindi vincolare il browser all’uso esclusivo di certificati specifici ed evitare la manipolazione della CA. Storicamente questo era possibile tramite HPKP , tuttavia è stato ufficialmente deprecato e rimosso dai browser moderni a causa del rischio di malfunzionamento al sito web interessato. Un errore umano nella gestione delle chiavi portava all’inaccessibilità totale e irreversibile del sito per gli utenti. Oggi, le linee guida internazionali impongono la mitigazione del rischio attraverso due pilastri: 

- **HSTS Preloading**: È una lista già presente nei browser moderni. Un dominio può venire iscritto al programma di HSTS Preloading, ancora prima di effettuare la prima connessione in assoluto verso quel sito, che dovrà negoziare esclusivamente un canale HTTPS. L’inserimento di questo header azzera la possibilità di attacchi SSLStripping.
- **Certificate Pinning**: Un framework aperto che impone la registrazione pubblica e immutabile di ogni certificato digitale emesso dalle CA all’interno di log crittografici verificabili. Grazie a esso, è possibile monitorare in tempo reale e impedisce ad attaccanti o CA compromesse di emettere certificati fraudolenti all’insaputa del legittimo proprietario del dominio.

Per implementare correttamente il protocollo HTTPS, bisogna apportare modifiche allo script. Nel codice del Flask, sono stati attivati due flag che permettono di eseguire la mitigazione, ovvero **SECURE_MODE** e **ENABLE HSTS**. Questi due flag globali apportano le seguenti modifiche al server: 

- **TLS 1.3 Obbligatorio**: Adesso la versione minima di TLS accettata è la 1.3, questo inibisce gli attacchi di downgrade logico a livello di handshake.
- **Suite Crittografica Recente**: La suite crittografica viene aggiornata, SHA-1 viene eliminato e vengono introdotti algoritmi **AEAD**, che sono notevolmente più sicuri.
- **Scambio delle Chiavi**: Anche lo scambio delle chiavi era vulnerabile, in quanto questo avveniva staticamente con RSA. Con la mitigazione, questo scambio diventa effimero obbligatorio (ECDHE/DHE). Questo garantisce la Perfect Forward Secrecy (PFS). Adesso la chiave privata RSA del server serve solo ad autenticare il server, non a derivare la chiave di sessione.
- **Direttive HSTS**: Obblighiamo il client alla conversione interna da HTTP a HTTPS, prevenendo attacchi come SSLStripping. Questo avviene con l’aggiunta della direttiva **preload** all’interno della stringa dell’header. Autorizza i motori di ricerca e i browser a inserire il dominio all’interno della lista di HSTS Preload globale. Il browser rifiuterà qualsiasi connessione HTTP nativa verso l’host prima ancora che il pacchetto venga immesso nella rete locale.

### 7. Verifica Efficacia Mitigazioni

Una volta attivati i flag di sicurezza sul server, è stata eseguita una nuova sessione di test. Il fine è quello di validare l’impatto delle contromisure applicate rispetto ai vettori d’attacco precedentemente descritti. Ripetendo la procedura di ARP Poisoning tramite Ettercap e Wireshark sulla macchina Linux, l’attaccante riottiene il posizionamento logico all’interno del canale. Tuttavia, l’efficacia dello sniffing attivo viene completamente neutralizzato. Questo perché il flusso di dati applicativo transita esclusivamente all’interno del tunnel crittografato TSL 1.3, e ispezionare i pacchetti tramite Wireshark non consente più la visualizzazione in chiaro del payload, preservando la Confidenzialità. Il warning fornito dal browser sul certificato non attendibile continua a essere mostrato. La cifratura del canale e la validità formale dell’emittente sono concetti distinti. Il canale è matematicamente sicuro e protetto da intercettazioni, ma il browser continua a segnalare che l’identità del server si basa su un Certificato Self-Signed. L’aggiunta dell’header HSTS non implica l’eliminazione del meccanismo di redirect, ma piuttosto viene modificato il flusso di connessione. Senza questo header, il client inviava una richiesta HTTP nativa sulla porta 5000, e il server Flask rispondeva e forzava il redirect sul sito HTTPS. Con HSTS invece il browser intercetta la richiesta HTTP ancora prima che questa possa generare pacchetti e lasciare l’interfaccia di rete. Da questo momento in poi tutti gli attacchi SSLStrip falliscono. Un attaccante posizionato da MitM con Ettercap non riceverà mai alcun pacchetto HTTP sulla porta 5000 da poter declassare o intercettare. Il traffico immesso sulla rete locale nasce già cifrato all’origine.

### 8. TLS Downgrade Fallisce

Adesso se l’attaccante prova a forzare la versione di TLS 1.2 con lo stesso comando di prima, riceverà il seguente log di errore: 

![Errore nel forzare TLS 1.2]({{ site.baseurl }}/assets/articolo2/erroretls12.png)

L’analisi dei log restituiti documenta il blocco immediato della sessione attraverso messaggi di errore nel log.  Infatti durante l’handshake TLS, il server che adesso non accetta più negoziazioni con versioni di TLS inferiori alla 1.3, risponde con SSL alert number 70. Quest alert fatale notifica formalmente che la versione del protocollo proposta è considerata obsoleta e rifiutata dalle policy di sicurezza. Poiché il server tronca la connessione a livello di handshake, le chiavi non vengono scambiate e di conseguenza il server non invia nemmeno il suo certificato X.509 pubblico, lasciando il client privo di qualsiasi informazione sull’identità dell’endpoint. La sessione viene terminata durante le fasi iniziali dell'handshake con un errore di terminazione, **SSL_Shutdown**, nessuna suite crittografica viene negoziata e nessuna chiave di sessione è stata generata o scambiata fra le parti. La mitigazione applicata a livello di codice ha configurato il server secondo i principi di Security by Design, blindando il canale di comunicazione sia contro l’intercettazione passiva dei dati sia contro i tentativi di declassamento logico del protocollo.

### 9. Conclusioni

Implementare HTTPS non è sufficiente se non lo si fa correttamente.  Lo sniffing passivo su HTTP ha dimostrato la totale vulnerabilità dei protocolli in chiaro, con crollo immediato della triade CIA. L’analisi formale tramite OpenSSL e Wireshark ha svelato l’illusione della sicurezza data da configurazioni crittografiche deboli (TLS 1.2 e suite basate su SHA-1), evidenziando la fattibilità teorica di attacchi di downgrade. Dopo l’hardenizzazione del server, con l’imposizione dello standard TLS 1.3 e l’header HSTS hanno dimostrato il successo della mitigazione. Il server ha cessato di adattarsi alle richieste insicure del client, stroncando sul nascere qualsiasi tentativo di downgrade o SSLStripping.