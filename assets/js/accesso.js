/* ==========================================================================
   PIERPONT by 4MC — accesso.js
   Flusso d'ingresso in due passi: credenziali, poi codice dal telefono.
   Stato d'invito (#invito): nuova password, poi il codice.
   Versione di prova: nessuna chiamata di rete. Qualsiasi email con la
   chiocciola e una password di almeno 8 caratteri portano al passo 2;
   qualsiasi codice a 6 cifre apre la piattaforma (sessionStorage pp_sessione).
   Accessi ospite (assets/js/ospiti.js, resta sul PC): un nome utente senza
   chiocciola e la sua password, controllata sull'impronta SHA-256 (mai in
   chiaro nel codice). Dopo il codice l'app mostra il nome dell'ospite
   (sessionStorage pp_utente) e, se previsto, propone la presentazione.
   Parametri utili: ?passo=2 apre subito il secondo passo (per le foto).
   ========================================================================== */
(function () {
  'use strict';

  var DURATA_CODICE = 5 * 60;                       // secondi di validità del codice
  var EMAIL_PROVA = 'marco.cassano@4mcadvisory.it'; // identità mostrata quando si apre ?passo=2 a freddo
  var DESTINAZIONE = 'app/index.html#/oggi';
  var ATTESA = 600;                                 // ms di «invio» simulato sui bottoni

  var radice = document.querySelector('[data-accesso]');
  if (!radice) { return; }

  var $ = function (sel, ctx) { return (ctx || radice).querySelector(sel); };
  var $$ = function (sel, ctx) { return Array.prototype.slice.call((ctx || radice).querySelectorAll(sel)); };
  var motoRidotto = function () {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  };

  /* Elementi ------------------------------------------------------------ */
  var pannelli = {};
  $$('[data-passo]').forEach(function (p) { pannelli[p.getAttribute('data-passo')] = p; });

  var segmenti = $$('.accesso__avanzamento span');
  var indicePasso = $('[data-indice-passo]');
  var indiceNome = $('[data-indice-nome]');
  var linkInvito = $('[data-invito-link]');
  var linkAccesso = $('[data-accesso-link]');

  var formCredenziali = $('#modulo-credenziali');
  var campoEmail = $('#email');
  var campoPassword = $('#password');
  var ricordami = $('#ricordami');
  var bottoneDimenticata = $('[data-dimenticata]');
  var notaPassword = $('#nota-password');

  var formCodice = $('#modulo-codice');
  var codice = $('.accesso__codice');
  var cifre = $$('.pp-codice__cifra');
  var erroreCodice = $('#codice-errore');
  var conto = $('[data-conto]');
  var contoRiga = $('.accesso__conto');
  var bottoneRimanda = $('[data-rimanda]');
  var esito = $('[data-esito]');
  var identita = $('[data-identita]');
  var identitaEmail = $('[data-email]');
  var bottoneIndietro = $('[data-indietro]');

  var formInvito = $('#modulo-invito');
  var campoInvitoEmail = $('#invito-email');
  var campoNuova = $('#nuova-password');
  var campoConferma = $('#conferma-password');
  var regole = {};
  $$('[data-regola]').forEach(function (li) { regole[li.getAttribute('data-regola')] = li; });

  var PASSI = {
    '1': { indice: 'Passo 1 di 2', nome: 'Credenziali', segmento: 0 },
    'invito': { indice: 'Passo 1 di 2', nome: 'Nuova password', segmento: 0 },
    '2': { indice: 'Passo 2 di 2', nome: 'Codice dal telefono', segmento: 1 }
  };

  var stato = {
    ospite: null,     // la scheda dell'ospite, se si entra con un nome utente
    passo: null,      // '1' | '2' | 'invito'
    origine: '1',     // da dove si è arrivati al passo 2 (per «Torna indietro»)
    email: '',
    scadenza: 0,      // istante (ms) in cui scade il codice
    timer: null,
    timerEsito: null,
    inTransizione: false,
    inInvio: false
  };

  /* Memoria locale, sempre protetta: in navigazione privata può mancare ---- */
  function leggi(deposito, chiave) {
    try { return window[deposito].getItem(chiave); } catch (e) { return null; }
  }
  function scrivi(deposito, chiave, valore) {
    try {
      if (valore === null) { window[deposito].removeItem(chiave); }
      else { window[deposito].setItem(chiave, valore); }
    } catch (e) { /* niente memoria: si va avanti lo stesso */ }
  }

  /* Errori sui campi a filetto ----------------------------------------- */
  function segnala(input, testo) {
    var campo = input.closest('.pp-campo');
    var messaggio = campo && campo.querySelector('.pp-campo__errore');
    input.setAttribute('aria-invalid', 'true');
    if (campo) { campo.classList.add('pp-campo--errore'); }
    if (messaggio) { messaggio.textContent = testo; messaggio.hidden = false; }
  }

  function pulisci(input) {
    var campo = input.closest('.pp-campo');
    var messaggio = campo && campo.querySelector('.pp-campo__errore');
    input.removeAttribute('aria-invalid');
    if (campo) { campo.classList.remove('pp-campo--errore'); }
    if (messaggio) { messaggio.hidden = true; messaggio.textContent = ''; }
  }

  function emailValida(valore) {
    return /^[^\s@]+@[^\s@]+$/.test(valore);
  }

  /* Cassaforte (solo la versione pubblicata online, assets/js/cassaforte.js): tutta la piattaforma è cifrata
     con una chiave che nasce da nome utente, password e codice insieme (PBKDF2 SHA-256 e AES-GCM).
     Senza le tre credenziali giuste il contenuto resta illeggibile, anche scaricando i file. */
  var CASSAFORTE = window.PP_CASSAFORTE || null;
  function daBase64(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) { u[i] = b.charCodeAt(i); } return u; }
  function chiaveDa(testo, sale, giri, uso) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(testo), 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (k) {
      var parametri = { name: 'PBKDF2', salt: daBase64(sale), iterations: giri, hash: 'SHA-256' };
      return uso === 'bit' ? crypto.subtle.deriveBits(parametri, k, 256)
        : crypto.subtle.deriveKey(parametri, k, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    });
  }
  function esadecimale(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join('');
  }
  /* Al massimo 5 tentativi sbagliati (nome utente, password o codice): poi l'accesso si blocca su questo dispositivo */
  var TENTATIVI_MAX = 5;
  var tentativiInMemoria = 0;
  function tentativi() {
    var n = parseInt(leggi('localStorage', 'pp_tentativi'), 10);
    return Math.max(n === n ? n : 0, tentativiInMemoria);
  }
  function bloccaAccesso() {
    $$('input, button', radice).forEach(function (el) { el.disabled = true; });
    var avviso = $('[data-blocco]');
    if (!avviso) {
      avviso = document.createElement('p');
      avviso.setAttribute('data-blocco', '');
      avviso.setAttribute('role', 'alert');
      avviso.className = 'pp-campo__errore';
      avviso.style.marginTop = '18px';
      var dove = pannelli[stato.passo] || pannelli['1'];
      dove.appendChild(avviso);
    }
    avviso.hidden = false;
    avviso.textContent = 'Troppi tentativi sbagliati: l’accesso è bloccato su questo dispositivo. Chiedi a Marco un nuovo accesso.';
  }
  function tentativoSbagliato() {
    tentativiInMemoria = tentativi() + 1;
    scrivi('localStorage', 'pp_tentativi', String(tentativiInMemoria));
    if (tentativiInMemoria >= TENTATIVI_MAX) { bloccaAccesso(); return true; }
    return false;
  }
  function restano() { return TENTATIVI_MAX - tentativi(); }

  function apriCassaforte(utente, password, codice) {
    return chiaveDa(utente + ':' + password + ':' + codice, CASSAFORTE.sale, CASSAFORTE.giri, 'chiave').then(function (k) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: daBase64(CASSAFORTE.iv) }, k, daBase64(CASSAFORTE.dati));
    }).then(function (b) { return new TextDecoder().decode(b); });
  }

  /* Ospiti: nome utente senza chiocciola, password controllata sull'impronta */
  function ospiteDi(nome) {
    var elenco = window.PP_OSPITI || {};
    var chiave = String(nome || '').trim().toLowerCase();
    return Object.prototype.hasOwnProperty.call(elenco, chiave) ? elenco[chiave] : null;
  }

  function impronta(testo) {
    if (!(window.crypto && crypto.subtle && window.TextEncoder)) { return Promise.reject(new Error('senza cifratura')); }
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(testo)).then(function (b) {
      return Array.prototype.map.call(new Uint8Array(b), function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join('');
    });
  }

  /* Mette il fuoco sul primo campo vuoto del pannello (o sul primo campo) */
  function mettiFuoco(pannello) {
    var campi = $$('input:not([type="checkbox"]):not([disabled])', pannello);
    if (!campi.length) { return; }
    var vuoto = null;
    for (var i = 0; i < campi.length; i++) {
      if (!campi[i].value) { vuoto = campi[i]; break; }
    }
    try { (vuoto || campi[0]).focus({ preventScroll: true }); } catch (e) { (vuoto || campi[0]).focus(); }
  }

  /* Avanzamento: segmenti fatti / corrente, «Passo n di 2» -------------- */
  function aggiornaAvanzamento(id) {
    var info = PASSI[id];
    segmenti.forEach(function (seg, i) {
      seg.classList.toggle('fatto', i < info.segmento);
      seg.classList.toggle('corrente', i === info.segmento);
    });
    indicePasso.textContent = info.indice;
    indiceNome.textContent = info.nome;
    // In alto a destra: l'invito quando si entra, l'accesso quando si attiva
    linkInvito.hidden = CASSAFORTE ? true : (id === 'invito');
    linkAccesso.hidden = (id !== 'invito');
  }

  /* Cambio di passo: il pannello corrente sale e sfuma, il nuovo entra da sotto */
  function mostraPasso(id, opzioni) {
    opzioni = opzioni || {};
    if (!pannelli[id] || stato.passo === id || stato.inTransizione) { return; }

    var da = stato.passo ? pannelli[stato.passo] : null;
    var a = pannelli[id];
    var subito = !!opzioni.subito || motoRidotto() || !da;

    stato.passo = id;
    aggiornaAvanzamento(id);

    function entra() {
      // Resta visibile solo il pannello richiesto (all'avvio il passo 1 è già in pagina)
      Object.keys(pannelli).forEach(function (k) {
        if (pannelli[k] !== a) { pannelli[k].hidden = true; pannelli[k].classList.remove('esce'); }
      });
      a.hidden = false;
      if (!subito) {
        a.classList.add('entra');
        void a.offsetWidth; // forza il ricalcolo: la transizione parte dallo stato «entra»
        a.classList.remove('entra');
      }
      if (id === '2') { preparaCodice(opzioni); } else { fermaConto(); }
      if (opzioni.fuoco !== false) { mettiFuoco(a); }
      stato.inTransizione = false;
    }

    if (subito) { entra(); return; }
    stato.inTransizione = true;
    da.classList.add('esce');
    window.setTimeout(entra, 230);
  }

  /* Bottone in attesa: filo che scorre, poi l'azione ------------------- */
  function invia(bottone, azione) {
    if (stato.inInvio) { return; }
    stato.inInvio = true;
    bottone.setAttribute('aria-busy', 'true');
    window.setTimeout(function () {
      bottone.removeAttribute('aria-busy');
      stato.inInvio = false;
      azione();
    }, motoRidotto() ? 0 : ATTESA);
  }

  /* ---------------------------------------------------------------------
     Passo 1 — credenziali
     --------------------------------------------------------------------- */
  // Occhio della password: mostra / nasconde, su tutti i campi che lo hanno
  $$('[data-occhio]').forEach(function (b) {
    b.addEventListener('click', function () {
      var campo = b.parentNode.querySelector('input');
      var mostra = campo.type === 'password';
      campo.type = mostra ? 'text' : 'password';
      b.setAttribute('aria-pressed', String(mostra));
      b.setAttribute('aria-label', mostra ? 'Nascondi la password' : 'Mostra la password');
      try { campo.focus({ preventScroll: true }); } catch (e) { campo.focus(); }
    });
  });

  // «Password dimenticata?»: una nota in linea, niente finestre
  bottoneDimenticata.addEventListener('click', function () {
    var aperta = bottoneDimenticata.getAttribute('aria-expanded') === 'true';
    bottoneDimenticata.setAttribute('aria-expanded', String(!aperta));
    notaPassword.hidden = aperta;
  });

  // Gli errori spariscono appena si corregge
  [campoEmail, campoPassword, campoInvitoEmail, campoNuova, campoConferma].forEach(function (c) {
    c.addEventListener('input', function () { pulisci(c); });
  });

  formCredenziali.addEventListener('submit', function (e) {
    e.preventDefault();
    if (stato.inInvio) { return; }
    var email = campoEmail.value.trim();
    var password = campoPassword.value;
    var primoErrore = null;

    if (CASSAFORTE) {
      var utente = email.trim().toLowerCase();
      if (!utente) { segnala(campoEmail, 'Scrivi il nome utente che hai ricevuto.'); campoEmail.focus(); return; }
      if (tentativi() >= TENTATIVI_MAX) { bloccaAccesso(); return; }
      if (utente !== CASSAFORTE.utente) { if (tentativoSbagliato()) { return; } segnala(campoEmail, 'Accesso riservato: usa il nome utente che hai ricevuto. Tentativi rimasti: ' + restano() + '.'); campoEmail.focus(); return; }
      if (!password) { segnala(campoPassword, 'Scrivi la password.'); campoPassword.focus(); return; }
      var bottone = formCredenziali.querySelector('[type="submit"]');
      bottone.setAttribute('aria-busy', 'true');
      chiaveDa(utente + ':' + password, CASSAFORTE.sale_verifica, CASSAFORTE.giri, 'bit').then(function (bit) {
        bottone.removeAttribute('aria-busy');
        if (esadecimale(bit) !== CASSAFORTE.verifica) { if (tentativoSbagliato()) { return; } segnala(campoPassword, 'La password non è giusta. Tentativi rimasti: ' + restano() + '.'); campoPassword.focus(); return; }
        stato.email = email.trim();
        stato.password = password;
        stato.ospite = { nome: CASSAFORTE.nome, presentazione: true };
        stato.origine = '1';
        mostraPasso('2');
      }, function () {
        bottone.removeAttribute('aria-busy');
        segnala(campoPassword, 'Questo browser non riesce a controllare la password: prova con Safari o Chrome aggiornati.');
      });
      return;
    }
    var ospite = email.indexOf('@') < 0 ? ospiteDi(email) : null;

    if (!email) { segnala(campoEmail, 'Scrivi la tua email di lavoro o il nome utente.'); primoErrore = campoEmail; }
    else if (email.indexOf('@') < 0 && !ospite) { segnala(campoEmail, 'Scrivi l’email di lavoro, oppure il nome utente che hai ricevuto.'); primoErrore = campoEmail; }
    else if (!ospite && !emailValida(email)) { segnala(campoEmail, 'L’indirizzo non è completo.'); primoErrore = campoEmail; }

    if (!password) { segnala(campoPassword, 'Scrivi la password.'); primoErrore = primoErrore || campoPassword; }
    else if (!ospite && password.length < 8) { segnala(campoPassword, 'La password ha almeno 8 caratteri.'); primoErrore = primoErrore || campoPassword; }

    if (primoErrore) { primoErrore.focus(); return; }

    function avanti() {
      stato.email = ospite ? email.trim() : email;
      stato.ospite = ospite;
      stato.origine = '1';
      invia(formCredenziali.querySelector('[type="submit"]'), function () {
        mostraPasso('2');
      });
    }
    if (!ospite) { stato.ospite = null; avanti(); return; }
    impronta(ospite.sale + ':' + email.trim().toLowerCase() + ':' + password).then(function (h) {
      if (h === ospite.impronta) { avanti(); }
      else { segnala(campoPassword, 'La password non è giusta.'); campoPassword.focus(); }
    }, function () {
      segnala(campoPassword, 'Apri la pagina dal server locale (127.0.0.1): serve per controllare la password.');
      campoPassword.focus();
    });
  });

  /* ---------------------------------------------------------------------
     Invito — nuova password con le regole in vista
     --------------------------------------------------------------------- */
  function verificaRegole() {
    var p = campoNuova.value;
    var c = campoConferma.value;
    var esiti = {
      lunghezza: p.length >= 12,
      numero: /\d/.test(p),
      simbolo: /[^0-9A-Za-zÀ-ÿ\s]/.test(p),
      uguali: p.length > 0 && p === c
    };
    Object.keys(esiti).forEach(function (k) {
      if (regole[k]) { regole[k].classList.toggle('ok', esiti[k]); }
    });
    return esiti;
  }

  campoNuova.addEventListener('input', verificaRegole);
  campoConferma.addEventListener('input', verificaRegole);

  formInvito.addEventListener('submit', function (e) {
    e.preventDefault();
    if (stato.inInvio) { return; }
    var email = campoInvitoEmail.value.trim();
    var esiti = verificaRegole();
    var primoErrore = null;

    if (!email) { segnala(campoInvitoEmail, 'Scrivi la tua email di lavoro.'); primoErrore = campoInvitoEmail; }
    else if (!emailValida(email)) { segnala(campoInvitoEmail, 'L’indirizzo non è completo.'); primoErrore = campoInvitoEmail; }

    if (!campoNuova.value) { segnala(campoNuova, 'Scegli una password.'); primoErrore = primoErrore || campoNuova; }
    else if (!esiti.lunghezza || !esiti.numero || !esiti.simbolo) {
      segnala(campoNuova, 'La password non rispetta ancora le regole qui sotto.');
      primoErrore = primoErrore || campoNuova;
    }

    if (!campoConferma.value) { segnala(campoConferma, 'Riscrivi la password per conferma.'); primoErrore = primoErrore || campoConferma; }
    else if (!esiti.uguali) { segnala(campoConferma, 'Le due password non coincidono.'); primoErrore = primoErrore || campoConferma; }

    if (primoErrore) { primoErrore.focus(); return; }

    stato.email = email;
    stato.ospite = null;
    stato.origine = 'invito';
    invia(formInvito.querySelector('[type="submit"]'), function () {
      mostraPasso('2');
    });
  });

  /* ---------------------------------------------------------------------
     Passo 2 — il codice a 6 cifre
     --------------------------------------------------------------------- */
  function formattaConto(secondi) {
    var m = Math.floor(secondi / 60);
    var s = secondi % 60;
    return m + ':' + (s < 10 ? '0' : '') + s;
  }

  function fermaConto() {
    if (stato.timer) { window.clearInterval(stato.timer); stato.timer = null; }
  }

  function aggiornaConto() {
    var resta = Math.max(0, Math.ceil((stato.scadenza - Date.now()) / 1000));
    conto.textContent = formattaConto(resta);
    contoRiga.classList.toggle('scaduto', resta === 0);
    if (resta === 0) {
      fermaConto();
      segnalaCodice('Il codice è scaduto. Mandane uno nuovo.');
    }
  }

  function avviaConto() {
    fermaConto();
    stato.scadenza = Date.now() + DURATA_CODICE * 1000;
    aggiornaConto();
    stato.timer = window.setInterval(aggiornaConto, 250);
  }

  function segnalaCodice(testo) {
    codice.classList.add('pp-codice--errore');
    cifre.forEach(function (c) { c.setAttribute('aria-invalid', 'true'); });
    erroreCodice.textContent = testo;
    erroreCodice.hidden = false;
  }

  function pulisciCodice() {
    codice.classList.remove('pp-codice--errore');
    cifre.forEach(function (c) { c.removeAttribute('aria-invalid'); });
    erroreCodice.hidden = true;
    erroreCodice.textContent = '';
  }

  // Ogni casella ricorda l'ultima cifra scritta: serve a capire, senza maxlength,
  // se una battuta è arrivata sopra una cifra già presente
  var memoria = cifre.map(function () { return ''; });

  function mettiCifra(j, valore) {
    cifre[j].value = valore;
    memoria[j] = valore;
  }

  function svuotaCodice() {
    cifre.forEach(function (c, j) { mettiCifra(j, ''); c.classList.remove('attiva'); });
    pulisciCodice();
  }

  function leggiCodice() {
    return cifre.map(function (c) { return c.value; }).join('');
  }

  function annuncia(testo) {
    esito.textContent = testo;
    if (stato.timerEsito) { window.clearTimeout(stato.timerEsito); }
    stato.timerEsito = window.setTimeout(function () { esito.textContent = ''; }, 6000);
  }

  // Scrive più cifre in fila a partire da una casella (incolla, riempimento automatico)
  function riempi(da, valore) {
    var inizio = valore.length >= cifre.length ? 0 : da;
    var k = 0;
    for (var j = inizio; j < cifre.length && k < valore.length; j++, k++) {
      mettiCifra(j, valore[k]);
    }
    var ultima = Math.min(cifre.length - 1, inizio + valore.length - 1);
    var prossima = Math.min(cifre.length - 1, inizio + valore.length);
    (cifre[prossima].value ? cifre[ultima] : cifre[prossima]).focus();
    pulisciCodice();
  }

  cifre.forEach(function (c, i) {
    c.addEventListener('focus', function () {
      cifre.forEach(function (x) { x.classList.remove('attiva'); });
      c.select();
    });

    // Niente maxlength sull'input: così il codice intero (riempimento automatico
    // dall'SMS, dettatura) arriva tutto e viene distribuito. Una battuta sopra
    // una cifra già presente la sostituisce (si guarda dov'è il cursore, non
    // e.data, che alcune tastiere non riempiono).
    c.addEventListener('input', function () {
      var grezzo = c.value;
      var prima = memoria[i];
      var v = grezzo.replace(/\D/g, '');
      var avanza = true;

      if (prima && grezzo.length === prima.length + 1) {
        var pos = typeof c.selectionStart === 'number' ? c.selectionStart : grezzo.length;
        var nuova = grezzo.charAt(Math.max(0, pos - 1));
        if (/\d/.test(nuova)) { v = nuova; }
        else { v = prima; avanza = false; }
      } else if (prima && grezzo && !v) {
        // Una lettera al posto della cifra selezionata: la cifra resta
        v = prima;
        avanza = false;
      } else if (v.length > 1) {
        // Codice intero arrivato in una casella già piena: si scarta la vecchia cifra
        if (prima && v.length > cifre.length && v.charAt(0) === prima) { v = v.slice(1); }
        riempi(i, v);
        return;
      }

      mettiCifra(i, v);
      if (v && avanza && cifre[i + 1]) { cifre[i + 1].focus(); }
      pulisciCodice();
    });

    c.addEventListener('keydown', function (e) {
      if (e.key === 'Backspace' && !c.value && i > 0) {
        e.preventDefault();
        mettiCifra(i - 1, '');
        cifre[i - 1].focus();
        pulisciCodice();
      } else if (e.key === 'ArrowLeft' && i > 0) {
        e.preventDefault();
        cifre[i - 1].focus();
      } else if (e.key === 'ArrowRight' && i < cifre.length - 1) {
        e.preventDefault();
        cifre[i + 1].focus();
      }
    });

    c.addEventListener('paste', function (e) {
      var dati = e.clipboardData || window.clipboardData;
      var testo = dati ? dati.getData('text') : '';
      var v = String(testo || '').replace(/\D/g, '');
      if (!v) { return; }
      e.preventDefault();
      riempi(i, v);
    });
  });

  // Entrando nel passo 2: identità, codice pulito, conto alla rovescia da 5:00
  function preparaCodice(opzioni) {
    var email = stato.email || leggi('localStorage', 'pp_email') || (opzioni && opzioni.demo ? EMAIL_PROVA : '');
    identitaEmail.textContent = email;
    identita.hidden = !email;
    svuotaCodice();
    esito.textContent = '';
    avviaConto();
    if (opzioni && opzioni.fuoco === false) { cifre[0].classList.add('attiva'); }
  }

  bottoneRimanda.addEventListener('click', function () {
    svuotaCodice();
    avviaConto();
    annuncia('Ti abbiamo mandato un nuovo codice.');
    cifre[0].focus();
  });

  bottoneIndietro.addEventListener('click', function () {
    mostraPasso(stato.origine || '1');
  });

  formCodice.addEventListener('submit', function (e) {
    e.preventDefault();
    if (stato.inInvio) { return; }
    var valore = leggiCodice();

    if (valore.length < cifre.length) {
      segnalaCodice('Scrivi tutte le sei cifre.');
      mettiFuoco(pannelli['2']);
      return;
    }
    if (Date.now() > stato.scadenza) {
      segnalaCodice('Il codice è scaduto. Mandane uno nuovo.');
      return;
    }

    if (CASSAFORTE) {
      var bottoneCodice = formCodice.querySelector('[type="submit"]');
      bottoneCodice.setAttribute('aria-busy', 'true');
      if (tentativi() >= TENTATIVI_MAX) { bloccaAccesso(); return; }
      apriCassaforte(stato.email.trim().toLowerCase(), stato.password || '', valore).then(function (pagina) {
        scrivi('localStorage', 'pp_tentativi', null);
        scrivi('sessionStorage', 'pp_sessione', 'ok');
        scrivi('sessionStorage', 'pp_presentazione', 'proponi');
        try { history.replaceState(null, '', location.pathname + '?ingresso=1&ospite=' + encodeURIComponent(CASSAFORTE.utente) + '&giro=1#/oggi'); } catch (e) { /* resta l'indirizzo */ }
        stato.password = null;
        document.open();
        document.write(pagina);
        document.close();
      }, function () {
        bottoneCodice.removeAttribute('aria-busy');
        if (tentativoSbagliato()) { return; }
        segnalaCodice('Il codice non è giusto. Tentativi rimasti: ' + restano() + '.');
      });
      return;
    }

    invia(formCodice.querySelector('[type="submit"]'), function () {
      scrivi('sessionStorage', 'pp_sessione', 'ok');
      // L'ospite porta nell'app il suo nome; e, se previsto, la proposta della presentazione guidata
      if (stato.ospite) {
        scrivi('sessionStorage', 'pp_utente', JSON.stringify({ nome: stato.ospite.nome, studio: stato.ospite.studio,
          iniziali: stato.ospite.iniziali, ospite: true }));
        if (stato.ospite.presentazione) { scrivi('sessionStorage', 'pp_presentazione', 'proponi'); }
      } else {
        scrivi('sessionStorage', 'pp_utente', null);
      }
      // «Ricordami»: si tiene solo l'email, per ritrovarla la prossima volta
      if (ricordami.checked && stato.email) { scrivi('localStorage', 'pp_email', stato.email); }
      else if (!ricordami.checked) { scrivi('localStorage', 'pp_email', null); }
      // Anche nell'indirizzo, per i browser che bloccano la memoria di sessione (per esempio dentro una pagina ospitata)
      var q = '?ingresso=1';
      if (stato.ospite) {
        q += '&ospite=' + encodeURIComponent(stato.email.trim().toLowerCase());
        if (stato.ospite.presentazione) { q += '&giro=1'; }
      }
      window.location.href = DESTINAZIONE.replace('#', q + '#');
    });
  });

  /* ---------------------------------------------------------------------
     Avvio: da dove si parte (URL) e cambi di ancora
     --------------------------------------------------------------------- */
  function passoDaUrl() {
    var ancora = window.location.hash.replace('#', '');
    if (ancora === 'invito') { return 'invito'; }
    var ricerca = window.location.search;
    if (/[?&]passo=2(&|$)/.test(ricerca)) { return '2'; }
    return '1';
  }

  // Email ricordata dall'ultima volta
  var ricordata = leggi('localStorage', 'pp_email');
  if (ricordata && !campoEmail.value) { campoEmail.value = ricordata; }

  var iniziale = CASSAFORTE ? '1' : passoDaUrl();
  if (iniziale === '2') {
    stato.email = campoEmail.value.trim();
    mostraPasso('2', { subito: true, fuoco: false, demo: true });
  } else {
    mostraPasso(iniziale, { subito: true, fuoco: false });
  }

  if (CASSAFORTE && tentativi() >= TENTATIVI_MAX) { bloccaAccesso(); }

  window.addEventListener('hashchange', function () {
    var ancora = window.location.hash.replace('#', '');
    if (ancora === 'invito') { mostraPasso('invito'); }
    else if (ancora === 'accesso' || ancora === '') { mostraPasso('1'); }
  });
})();
