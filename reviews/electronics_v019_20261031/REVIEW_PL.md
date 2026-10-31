# Recenzja doradcza artykułu dla planowanego zgłoszenia do Electronics

**Manuskrypt:** *Block-Position Structure in Reduced ChaCha20 and Salsa20: Experimental Diagnostics of IV Diffusion*, v0.19.0, 11 stron z bibliografią, 40 źródeł. **Data oceny:** 31 października 2026 r. **Zakres:** pełna lektura aktualnego tekstu, pięć osobnych perspektyw i wybrane kontrole algebraiczne, danych oraz kodu; bez zmian w artykule.

**Rekomendacja: celowana rewizja przed zgłoszeniem.** Artykuł ma spójny, obroniony rdzeń naukowy. W sprawdzonym zakresie nie wykryto błędu matematycznego, liczbowego ani pseudoreplikacji unieważniających główne wyniki. Najważniejsze ryzyko recenzenckie dotyczy wykazania nowości oraz precyzji krótkich podsumowań. Zidentyfikowane poprawki można oprzeć na istniejącym materiale; nie uzasadniają automatycznie nowych kohort, ataku ani przywracania suplementu.

To moja synteza pięciu **opinii doradczych**, a nie decyzja redakcji, prognoza akceptacji ani mechaniczny wynik pełnego panelu ARS. Formalny workflow ARS został przerwany przed recenzjami z powodu niespełnionej zależności walidatora. Aktualnych wymagań Electronics i pierwszeństwa względem pełnych tekstów najbliższych prac nie zweryfikowano przez sieć. Dlatego nie przypisuję publikacji procentowej szansy ani potwierdzonej zgodności z bieżącymi kryteriami czasopisma.

## Co broni wartości pracy

**Ścisły wynik lokalny ma treść niezależną od estymatora entropii.** W §4.1 równania (7)–(8) opisują warunkową mapę słowa 7, jej rangę oraz średnią odpowiedź na 32 singletony. Dowód przez rozłączne przedziały przeniesień jest przekonujący; obejmuje przepełnienie, najstarszy bit i skrajne wartości C. Osobna kontrola małych szerokości 1–7 bitów nie znalazła kontrprzykładu w 21 844 parach (C,u). To kontrola pomocnicza, nie zamiennik dowodu dla 32 bitów. Trafnie odróżniono rangę warunkowej mapy jednego słowa od rangi lub liniowości całego szyfru.

**Interwencje wyjaśniają, gdzie powstaje różnica.** Tabela 2 i §4.2 pokazują lukę Salsa20 już bez feed-forward, 0,72940 bitu, oraz jej sparowany wzrost o 0,05865 po dodawaniu. Pochodne mieszane sprawdzają inną, algebraicznie przewidzianą własność. Nie sprowadzono tego wyniku do ogólnego stwierdzenia, że dwie rundy słabo mieszają bity. Uczciwie pozostawiono nierozstrzygnięty zaplanowany kontrast ChaCha20 z p=0,108.

**Kontrole pomiaru mają sens i potwierdzenie liczbowe.** Z zapisanych wyników odtworzono redukcje modułu kontrastu AC o 95,8793% i 94,1716%, zgodne z podanymi 96% i 94%. Zachowanie wartości HW oraz DC przez rotacje uzasadnia wniosek o wrażliwości na kolejność. Poprawna tożsamość DC/AC i zmiana znaku luki ChaCha20 po zmianie agregacji pokazują, dlaczego pojedyncza entropia nie porządkuje jakości dyfuzji.

**Ewaluacja modeli nie ukrywa niekorzystnych wyników.** Kod i manifesty wspierają rozdzielenie treningu 840–919 od ewaluacji 1200–1279 oraz zamrożenie predykcji przed generacją ewaluacji. Sprawdzone tabele potwierdzają poprawę M1 dla sześciu średnich widm AC, przy lepszych lukach entropii M0 dla wszystkich trzech szerokości ChaCha20. Przedziały mają jawnie warunkowy zakres. Hash i lokalna kolejność wykonania nie są jednak publicznym, niezależnym znacznikiem czasu.

## Poprawki istotne przed zgłoszeniem

### 1. Wykazać dokładnie, co jest nowe względem najbliższych wyników dwurundowych

**Źródło uwagi:** opinie kryptograficzna, redakcyjna i kontrargument; §2 oraz §4.1. Przegląd odwołuje się do „two-round key--IV criteria” i pracy Dey i współautorów z 2025 r., ale nie zestawia jej konkretnych twierdzeń z obecną afinicznością słowa 7, rangą i średnią singletonową. Zdanie „The published internal biases do not numerically predict these HW contrasts” rozróżnia obserwable, lecz nie rozstrzyga pierwszeństwa wyników algebraicznych.

**Znaczenie:** recenzent może uznać nowe pomiary za konsekwencje znanych już zależności, jeżeli autor nie wskaże granicy wkładu. Nie ustaliliśmy, że twierdzenie jest znane; ustaliliśmy, że tekst nie pozwala dostatecznie ocenić jego nowości. Rozstrzygnięcie wymaga przeczytania najbliższych cytowanych źródeł.

**Minimalna poprawka:** zastąpić część ogólnego wyliczenia literatury krótkim porównaniem: jaki obiekt i rundy bada wcześniejsza praca, jaką własność ustala, a co dokładnie dodaje ten artykuł. Rozdzielić nowy wynik, ponowne wyprowadzenie znanej przesłanki i nowe powiązanie konstrukcji z pomiarem. Nie dodawać deklaracji pierwszeństwa bez sprawdzenia źródeł.

### 2. Nazwać właściwe odwzorowanie przy utracie afiniczności

**Źródło uwagi:** kontrargument; abstrakt, §4.1, §4.3 i konkluzja. Świadkowie przejścia do trzeciej rundy dotyczą `W_r[7]`, czyli wyjścia `none`. Wcześniejsza ranga dotyczy mapy `f_C` po finalizacji `add`, a utrzymujący się kontrast widmowy także mierzy wyjście `add`. §4.3 rozróżnia te sytuacje; zdanie abstraktu „A third-round update ends the sampled conditional affinity” może je zlać.

**Znaczenie:** niezerowa pochodna rdzenia nie stanowi sama w sobie dowodu nieafiniczności słowa po modularnej finalizacji. Nie podważa to wykazanej współobecności lokalnej nieliniowości rdzenia i struktury standardowego wyjścia.

**Minimalna poprawka:** w abstrakcie i konkluzji użyć określenia „conditional affinity of the unfinalized word-7 map”, a drugi wynik przypisać standardowemu wyjściu. W §4.1 warto dodatkowo krótko wykazać niezależność argumentów drugiej aktualizacji od początkowego x7; sam fakt powtórzenia roli c nie jest takim dowodem, choć w tej konstrukcji przesłanka jest prawdziwa. Nie potrzeba nowego eksperymentu.

### 3. Umożliwić odnalezienie konkretnego archiwum dowodowego

**Źródło uwagi:** opinie metodologiczna, kryptograficzna i redakcyjna; Data Availability Statement. Tekst opisuje zawartość archiwum i podaje „No public DOI has yet been assigned”, lecz nie wskazuje adresu ani jednoznacznej dostępnej wersji.

**Znaczenie:** lokalne materiały są obszerne, ale czytelnik samego artykułu nie potrafi ich odnaleźć. Uwaga dotyczy odtwarzalności, nie domniemanego wymogu DOI w Electronics.

**Minimalna poprawka:** dodać działający odsyłacz do konkretnej wersji albo jednoznacznie wskazać przekazany recenzentom pakiet danych i kodu wraz z manifestem. DOI jest jednym ze sposobów identyfikacji, nie jedynym. Archiwum danych nie wymaga osobnego suplementu tekstowego.

## Zalecane doprecyzowania w obecnej objętości

| Miejsce | Uwagi i minimalne działanie |
|---|---|
| §3.3, testy sign-flip | Podać H0, statystykę oraz założenie symetrii lub wymienności uzasadniające zmianę znaków. Sama niezależność kluczy i zerowa średnia nie gwarantują dokładnego testu skończonopróbkowego. Jeżeli uzasadnienie jest przybliżone, tak je nazwać. Nie wykryto przez to błędnego efektu ani błędnego p. |
| §3.4, błąd widmowy L1 | Wprost podać kolejność: moce po bazach → normalizacja dla klucza i maski → średnia po maskach i kluczach → L1. Wskazać, że chodzi o widma szyfru, nie o odejmowanie widma referencyjnego, i że zakres odległości wynosi 0–2. To usuwa napięcie z ogólnym „For every statistic” w §3.2. |
| Rysunek 2 / §4.4 | Rozważyć zastąpienie jednego panelu skalarnego rzeczywistym widmem AC: obserwacje, M0, M1, z zaznaczeniem częstotliwości blokowej. Artykuł raportuje błędy widma, ale nie pokazuje samego widma. Dane już istnieją. To poprawka prezentacji, nie dowód wadliwości modelu. |
| §3.2, szerokości segmentów | Krótko dopowiedzieć, że sumowanie sąsiednich HW połączone z decymacją zmienia obserwablę; przy stałym oknie W odstęp fizycznych częstotliwości pozostaje 1/W. Autor już stwierdza zmianę estymatora, więc jest to doprecyzowanie, nie nowo wykryte przemilczenie. |
| §3.4 / rysunek 2 | Pokazać choć reprezentatywną skalę istniejących MCSE lub wskazać konkretny plik w dostępnym archiwum. Dla M1/Salsa20/128 MCSE luki wynosi około 0,000381 bitu wobec błędu predykcji około 0,006671. Nie wymaga to propagacji niepewności treningu dla obecnego, warunkowego twierdzenia. |

## Rozstrzygnięcie różnic między opiniami

Opinia metodologiczna rekomenduje *minor corrections*, widmowa ograniczone poprawki opisu i prezentacji, a kryptograficzna, redakcyjna i kontrargument — celowaną rewizję przed zgłoszeniem. Nie jest to rozbieżność w sprawie wykrytego błędu obliczeń: dotyczy głównie wagi niewyjaśnionej nowości. W mojej syntezie porównanie z najbliższą literaturą należy wykonać przed wysłaniem, nawet jeśli końcowa poprawka zajmie tylko jeden akapit. Nie przenoszę tych opinii na niewyliczoną mechaniczną kategorię ARS ani procent akceptacji.

Uwaga kontrargumentu o braku ilościowego wyprowadzenia całej luki około 0,79 bitu jest ograniczeniem zakresu. Obecny tekst deklaruje połączenie poziomów dowodu, a nie pełne wyprowadzenie tej liczby z rangi słowa 7. Wystarczy konsekwentnie odróżniać ścisłe lokalne twierdzenie, sparowany efekt finalizacji i empiryczną predykcję widma. Nie uznaję pełnej dekompozycji luki lub nowej ablacji za warunek dla obecnych tez.

Nie przyjmuję propozycji przywrócenia suplementu ani dokładania wielu tabel. Takie sugestie pojawiają się w opcjonalnych częściach surowych opinii metodologicznej i widmowej, ale są niezgodne z ograniczeniem autora. Jeżeli potrzebne jest miejsce, można skrócić opis pomocniczych szyfrów w §5, zachowując ich najważniejsze wnioski, zwłaszcza przykład A5/1. Wykres widma może zastąpić istniejący panel. Opis rozkładu błędów per maska, nowe przesunięcia segmentacji, niepewność treningu i dalsze rundy pozostają opcjonalnymi badaniami.

## Ślad wykonania i ograniczenia

Pięć opinii przygotowano w osobnych natywnych kontekstach, bez przekazywania wzajemnych ocen przed ich ukończeniem. To rozdzielenie kontekstów i perspektyw, nie dowód niezależnych błędów: wszystkie korzystały z bieżącej rodziny modelu Codex, a dokładny identyfikator modelu nie był osobno poświadczony. Autor niniejszej syntezy uczestniczył wcześniej w redakcji artykułu. Nie było ludzkiego panelu ani przeglądu przez zewnętrzną rodzinę modeli.

[ARS Academic Research Suite](/home/paugustynowicz/.codex/plugins/cache/ars-codex/ars-codex/3.24.0/skills/academic-research-suite/SKILL.md) uruchomiono w trybie recenzji. Jednak `check_sprint_contract.py` zakończył się błędem `AttributeError`, ponieważ lokalny `jsonschema 3.2.0` nie zawiera `Draft202012Validator`. [Protokół kontraktu](/home/paugustynowicz/.codex/plugins/cache/ars-codex/ars-codex/3.24.0/skills/academic-research-suite/ars/academic-paper-reviewer/references/sprint_contract_protocol.md) wymaga przy błędzie infrastruktury „abort the round, no retry”. Nie osłabiano walidatora. Formalny panel ARS, jego mechaniczna decyzja i pakiet Schema 6 nie zostały wykonane; dalsza recenzja była jawnym trybem doradczym.

Dostęp do stron MDPI również pozostał niedostępny: po błędzie DNS próba rozszerzonego dostępu nie została wykonana, ponieważ automatyczny mechanizm zatwierdzania zakończył się błędem 404. Nie był to werdykt, że odczyt jest niebezpieczny. Nie obchodzono kontroli. Nie potwierdzono aktualnych zasad wydawcy ani nie wykonano nowego sieciowego audytu cytowań.

Źródła poszczególnych opinii:

- [Metodologia i statystyka](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v019_20261031/methodology_advisory.md)
- [Kryptografia i algebra](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v019_20261031/cryptography_advisory.md)
- [Pomiary widmowe](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v019_20261031/spectrum_advisory.md)
- [Znaczenie i redakcja naukowa](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v019_20261031/editorial_advisory.md)
- [Kontrargument](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v019_20261031/counterargument_advisory.md)

Kopie wejściowe i ich hashe zapisano w tym katalogu. Strukturalny preflight PDF przeszedł dla 11 stron; nie jest to certyfikat poprawności merytorycznej. Kontrole liczb były wybiórcze, bez powtarzania całej kampanii eksperymentalnej. Manuskrypt, bibliografia, dane i kod naukowy pozostają bez zmian.
