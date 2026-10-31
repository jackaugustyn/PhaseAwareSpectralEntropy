# Ponowna recenzja doradcza — wersja 0.20

**Rekomendacja: domknąć porównanie z najbliższą literaturą przed zgłoszeniem do Electronics.** Poprawki usunęły wcześniejsze niejednoznaczności matematyczne, statystyczne i pomiarowe. Pozostałe istotne zastrzeżenie dotyczy wykazania odrębności wkładu. W sprawdzonym zakresie nie znaleziono nowego błędu podważającego główne wyniki.

Przedmiotem oceny jest *Block-Position Structure in Reduced ChaCha20 and Salsa20: Experimental Diagnostics of IV Diffusion*, v0.20.0, 31 października 2026 r. Artykuł ma **11 stron łącznie z 40 pozycjami bibliografii**, dwie ryciny i dwie tabele, bez suplementu. Recenzja porównuje go z v0.19 według wcześniejszych uwag, bez zmiany kryteriów po zobaczeniu poprawki. Nie zmieniano artykułu ani materiałów naukowych.

## Weryfikacja wcześniejszych uwag

| Punkt | Wynik | Podstawa oceny |
| --- | --- | --- |
| N1. Odrębność wkładu wobec najbliższych wyników dwurundowych | **Częściowo usunięte** | `related_work_comparison.tex:10` wyraźnie łączy warunkowe tożsamości, interwencje i empiryczną rekonstrukcję widm. Nie deklaruje pierwszeństwa słabej dyfuzji ani różnic wyższych rzędów. Nadal brakuje porównania z konkretną własnością ustaloną w najbliższej pracy Dey i współautorów. |
| N2. Właściwa mapa przy utracie afiniczności | **Usunięte** | Abstrakt, §4.3 i konkluzja wskazują niezfinalizowane słowo 7. Utrzymujący się sygnał widmowy dotyczy osobno standardowego wyjścia add (`main.tex:22,170–172,204`). |
| N3. Identyfikowalne archiwum dla recenzentów | **Usunięte na etapie przygotowania zgłoszenia** | Deklaracja dostępności podaje istniejący ZIP v0.20.0, manifest i konkretny plik wyników (`main.tex:210`). Zawartość odpowiada artykułowi. Pakiet trzeba faktycznie przekazać przy zgłoszeniu; jego istnienie lokalnie nie oznacza publicznego zdeponowania. |
| N4. Założenia testów sign-flip | **Usunięte** | Podano hipotezę zerowej średniej, statystykę, jednostkę resamplingu, wzór plus-one i mocniejsze założenie niezmienniczości rozkładu względem zmian znaków. Ważność korekty Holma jest wyraźnie warunkowa (`main.tex:105–107`). |
| N5. Definicja błędu widmowego L1 | **Usunięte** | Jawna kolejność: średnia mocy po bazach → normalizacja AC dla klucza i maski → średnia po maskach i kluczach → L1; zakres 0–2, bez odejmowania referencji (`main.tex:78,123`). |
| N6. Pokazanie rzeczywistych widm | **Usunięte** | Rysunek 2a,b porównuje obserwacje z M0/M1. Transformacja danych, częstotliwości, składanie par sprzężonych i przedziały są zgodne z opisem (`main.tex:184–185`). |
| N7. Agregacja a rozdzielczość częstotliwościowa | **Usunięte** | Wzór i opis rozróżniają sumowanie z decymacją od stałego odstępu fizycznych częstotliwości 1/W (`main.tex:60`). |
| N8. Błąd symulacji Monte Carlo | **Usunięte** | MCSE 0,00038 bitu zestawiono z błędem predykcji 0,00667; oddzielono niepewność symulacji od niepewności kluczy ewaluacyjnych (`main.tex:123,188`). |
| N9. Niezależność stałej C od drugiego słowa nonce | **Usunięte** | Wypisano obie aktualizacje słowa 7 i argument niezależności właściwych słów po pierwszej rundzie; użyto początkowego x15 (`arx_mechanism_compact.tex:5–10`). |

To rozstrzygnięcia odziedziczonych uwag, a nie dziewięć równoważnych składników punktowej oceny publikacyjnej. Otwarty N1 ma większe znaczenie dla decyzji redaktora niż liczba wykonanych poprawek opisowych.

## Co obecna wersja broni lepiej

**Lokalny wynik algebraiczny jest teraz samodzielnie uzasadniony.** Czytelnik może prześledzić, dlaczego stała C nie zależy od x7, a następnie sprawdzić dowód afiniczności, rangi i średniej odpowiedzi singletonowej. Pozostało jasne ograniczenie do warunkowego odwzorowania jednego słowa. Kontrola 21 844 pomocniczych przypadków dla szerokości 1–7 bitów nie znalazła kontrprzykładu; dowód w tekście pozostaje podstawą wyniku 32-bitowego.

**Zniknęło utożsamienie dwóch różnych obserwacji przejścia między rundami.** Niezerowe pochodne dotyczą niezfinalizowanej mapy, a widmo — standardowego wyjścia po dodawaniu. Ponowne zliczenie zapisanych checkpointów potwierdza 10 240 zer przed wskazaną aktualizacją i 10 240 wartości niezerowych po niej, ze średnią HW 15,84033203125. To wspiera dokładnie ograniczony wniosek zawarty w nowym tekście.

**Nowa rycina pokazuje, co modele rzeczywiście odtwarzają.** Zamiast samych skalarów widać składową blokową, harmoniczną i tło widma. Dla 128-bitowej segmentacji odtworzono L1 M0/M1: 0,32199/0,08436 dla ChaCha20 oraz 0,10100/0,01043 dla Salsa20. Zweryfikowano też pozostałe odległości, sposób składania przedziałów oraz pomiar od surowych HW dla dwóch kluczy ewaluacyjnych. Tekst nadal uczciwie podaje, że M0 trafniej odtwarza wszystkie trzy luki entropii ChaCha20. Poprawa widma nie została zamieniona w twierdzenie o uniwersalnej przewadze M1.

**Opis wnioskowania odpowiada jego rzeczywistym ograniczeniom.** Nowa deklaracja założeń nie dowodzi symetrii rozkładów pod hipotezą zerową, lecz usuwa wcześniejszą niejasność co do warunków kalibracji. Efekty i przedziały pozostają istotną częścią argumentu. Zapisane wartości pozwalają odtworzyć korekty Holma i przykład MCSE; nie trzeba traktować bardzo małych p jako bezwarunkowego dowodu poprawności modelu losowania.

## Jedno pozostałe istotne zadanie

W §2 należy porównać obecny wynik z konkretnym fragmentem pracy *Significantly Improved Cryptanalysis of Salsa20 with Two-Round Criteria* (Dey i współautorzy, pozycja identyfikowana w lokalnej bibliografii przez DOI `10.46586/tosc.v2025.i1.420-443`). Potrzebne jest ustalenie:

1. Jakie wejścia, rundy i postać wyjścia bada wcześniejszy wynik.
2. Czy obejmuje tę samą tożsamość słowa 7, równoważną własność afiniczną lub wynik o randze/odpowiedzi singletonowej.
3. Co w obecnym artykule jest znaną przesłanką, co jej wyprowadzeniem, a co własnym wynikiem lub nowym sprawdzonym powiązaniem.

Nie ustalono, że obecny wynik został wcześniej opublikowany. Nie ustalono też jego pierwszeństwa: pełnego tekstu najbliższego źródła nie odczytano. Rezygnacja z niezweryfikowanej deklaracji nowości była prawidłowa, ale nie zastępuje porównania. Minimalnym następnym krokiem jest odczyt źródła i celowany akapit; dalszy zakres rewizji zależy od tego, jaki stopień pokrywania się wyników zostanie stwierdzony. Jeżeli przesłanka jest znana, trzeba ją odpowiednio przypisać i oprzeć oryginalność na rzeczywiście odrębnych rezultatach.

W obecnej kontroli nie znaleziono podstaw do wymagania nowych kohort, pełnego ataku czy przywrócenia suplementu. Artykuł utrzymuje spójną oś: lokalna własność konstrukcji → efekt finalizacji → konsekwencje dla pomiaru. Największa poprawa względem v0.19 dotyczy przejrzystości i weryfikowalności tej argumentacji. Ryzyko oceny jako wkładu przyrostowego pozostaje uzależnione przede wszystkim od otwartego porównania literaturowego.

## Zakres kontroli i status ARS

Recenzję przygotowano z użyciem instrukcji [ARS-Codex](</home/paugustynowicz/.codex/plugins/cache/ars-codex/ars-codex/3.24.0/skills/academic-research-suite/SKILL.md>) jako **weryfikację doradczą**. Formalny tryb `re-review` nie został wykonany: poprzednia runda doradcza nie wytworzyła wymaganych artefaktów kontraktu, a sprawdzony lokalny `jsonschema 3.2.0` nadal nie zawiera `Draft202012Validator`. Nie utworzono zastępczego kontraktu ani certyfikowanej decyzji. Szczegóły zapisano w `runtime_status.json`.

Trzy opinie specjalistyczne powstały w świeżych, osobnych kontekstach bez przekazywania sobie obecnych raportów. Recenzenci nie otwierali `REVIEW_RESPONSE_V020.md` przed zapisaniem swoich ocen; recenzent metodologiczny podczas kontroli archiwum zobaczył jednak autorski opis zmian w jego metadanych. Autor syntezy uczestniczył w redagowaniu artykułu i znał odpowiedź na uwagi. Nie deklarujemy pełnego zaślepienia, niezależnych procesów błędu, ludzkiego panelu ani przeglądu przez inną rodzinę modeli. Wynik pozostaje `NOT_CALIBRATED`.

Nie zweryfikowano bieżących zasad *Electronics* ani pełnych tekstów najbliższych cytowanych prac. Ocena odnosi się do wcześniejszych kryteriów naukowych i planowanego czasopisma; nie jest decyzją redakcji, potwierdzeniem aktualnej zgodności z jego wymaganiami ani procentową prognozą przyjęcia.

Sprawdzono CRC i SHA-256 archiwów, zgodność wszystkich 893 plików pakietu badawczego z workspace oraz obecność właściwego PDF i wskazanego pliku wyników. Pakiet redakcyjny zawiera 13 plików. Dane i kod pozostają dostępne w odrębnym archiwum badawczym; nie jest ono suplementem tekstowym. Nie wykonywano nowych eksperymentów szyfrowych ani nowych symulacji modeli. Kopia ocenianego tekstu, różnica względem v0.19, skróty wejść i wyniki kontroli znajdują się obok tego raportu.

Raporty szczegółowe:

- [Kryptografia i kontrargument](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v020_20261031/cryptography_verification.md)
- [Metodologia i statystyka](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v020_20261031/methodology_verification.md)
- [Pomiary widmowe](/home/paugustynowicz/PhaseAwareSpectralEntropy/reviews/electronics_v020_20261031/spectrum_verification.md)
