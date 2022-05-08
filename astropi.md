# AstroPi
AtroPi è una competizione per teenager europei a tema STEM. Ogni team deve progettare un esperimento scientifico che poi viene eseguito sulla stazione spaziale internazionale
attraverso due raspberry pi (Izzy e Ed). Poi si deve scrivere il report dove si spiega l'esperimento, il procedimento, l'analisi dati e le conclusioni. Una giuria infine legge 
le relazioni e vengono decretati i vincitori.

Si può dire che questa è stata la mia prima "esperienza di laboratorio seria".

Così ho iscritto il mio team, [**AstroLorenzini**](https://istitutolorenzinipescia.edu.it/), composto solo da me!
## L'idea
Farsi venire in mente una buona idea per un esperimento è molto difficile. Lo standard dei vincitori delle edizioni precedenti era molto alto.

Alla fine ho deciso di determinare l'eccentricità dell'ISS attorno al pianeta. Ma come fare? XD

Per riuscire a trovare un modo ci ho messo diverso tempo (e varie ricerche su google per studiare argomenti di fisica che non avevo mai visto). 

## Dettagli 
L'esperimento viene eseguito sulla ISS tramite due computer Izzy e Ed (due raspberry pi 3, uno affacciato a una finestra con una telecamera rivolta verso la terra e
l'altro dentro il modulo Columbus). Questi computer sono stati regalati dalla raspberry-pi foundation e portati in orbita con la missione Principia del 2015.

Per il mio esperimento ho usato Izzy, non perchè avessi veramente necessità di fotografie. Il mio esperimento non si basa su image analysis, ma perchè ho pensato che avere delle foto dallo spazio scattate da me (in un certo senso) sia figo. Tutto quà ;)

Ho usato il raspberry-pi (con tanto di sensori e camere) che mi è stato inviato dalla ESA per scrivere e testare il codice python da spedire sulla ISS.
Il codice che ho scritto è molto semplice, ogni 12 secondi scatta una fotografia e raccoglie dati da tutti i sensori del sensehat montati sul computer. Questi includono giroscopio, accelerometro, magnetometro, sensore di temperature, umidità ecc...
Non tutti mi servivano, ma non si sa mai. Inoltre se mi fosse venuta un'altra idea per un eseperimento futuro in questo modo ho tutti i dati a disposizione.

Non ho fatto alcun tipo di analisi dati in orbita. Perché rischiare che qualcosa vada storto? Meglio tenere il codice semplice. Tutta l'analisi dati è stata eseguita sulla terraferma.

## Report e risultati
Il mio lavoro è stato selezionato tra gli *Highly Commended*, ossia tra i lavori che hanno dimostrato grande merito scientifico e un uso innovativo dell'hardware astropi.

Qui puoi trovare i [codici usati](https://github.com/LucaPalumbo/AstroLorenzini) per l'analisi dati.
Qui trovi invece la lista di tutti i [vincitori e highly commended](https://www.esa.int/Education/AstroPI/And_the_finalists_of_the_2019-20_Astro_Pi_Challenge_Mission_Space_Lab_are) compreso il mio [report finale](https://esamultimedia.esa.int/docs/edu/ap_2020/AstroLorenzini_report.pdf)

