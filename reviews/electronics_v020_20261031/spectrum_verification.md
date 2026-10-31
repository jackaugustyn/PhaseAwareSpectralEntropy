# Doradcza weryfikacja v0.20: pomiary widmowe

**Wynik: N5, N6 i N7 są addressed. Nie stwierdzam nowego defektu w tym zakresie ani potrzeby dalszej obowiązkowej poprawki.** Nowy rysunek pokazuje rzeczywiste średnie widma AC, a opis definiuje jednoznacznie normalizację, odległość i znaczenie agregacji. Zachowano ograniczone wnioski o modelach.

Ocena dotyczy artykułu dla *Electronics* i kryteriów zapisanych w `inherited_criteria.md`. Najpierw przeczytałem ten plik oraz `reviews/electronics_v019_20261031/spectrum_advisory.md`, następnie porównałem odpowiednie fragmenty v0.19 z aktualnym `doc_stream_ciphers/main.tex` i jego dwoma wejściami tekstowymi. Obejrzałem rasteryzację istniejącego `publication_reviewed_spectrum.pdf`, przeczytałem generator i manifest oraz wykonałem ograniczone kontrole zapisanych danych. Nie czytałem odpowiedzi autora `REVIEW_RESPONSE_V020.md` ani innych raportów bieżącej rundy przed zapisaniem tej opinii. Nie uruchamiałem nowych szyfrów ani ponownej generacji Monte Carlo; nie zmieniałem manuskryptu, danych ani rysunków.

To osobna opinia doradcza, **NOT_CALIBRATED**, nie zwalidowany panel ani wynik formalnego kontraktu ARS. Brak kompletnego kontraktu i walidatora z poprzedniego przebiegu nie został zastąpiony deklaracją zgodności. Odrębny kontekst tej opinii nie dowodzi niezależności procesów błędu.

## Domknięcie odziedziczonych kryteriów

| Kryterium | Stan | Dowód i porównanie z v0.19 | Minimalna pozostała poprawka |
| --- | --- | --- | --- |
| **N5 — definicja widmowego L1** | **addressed** | `main.tex:123` podaje cztery moce bazowe → normalizacja AC osobno dla klucza i maski → średnia po maskach i kluczach → L1, zakres `[0,2]` oraz brak odejmowania referencji. `main.tex:78` ogranicza ogólną definicję kontrastu do porównań szyfr–referencja. Usuwa to niejednoznaczność v0.19 (`manuscript.tex:86,129`). Zgadza się z `experiments/stream_rounds_study/arx_spectral_prediction.py:129–139,224–236,407–413`. | Brak. |
| **N6 — pokazanie rzeczywistego widma** | **addressed** | Zamiast skalarnego panelu v0.19 (`manuscript.tex:223–224`) aktualny rysunek, włączony przez `main.tex:184`, pokazuje obserwacje/M0/M1 dla obu szyfrów przy `s=128`, `W=8192`. Podpis (`main.tex:185`) podaje brak referencji, składanie par, pominięcie DC, pojedyncze liczenie Nyquista, częstotliwości blokowe i punktowy zakres przedziałów. Generator i dane potwierdzają te informacje; szczegóły poniżej. | Brak. Jeden pokazany wariant szerokości spełnia odziedziczone minimum. |
| **N7 — szerokość segmentu a częstotliwość** | **addressed** | `main.tex:60` zastępuje skrót v0.19 (`manuscript.tex:68`) wzorem `h^(gs)_j = sum_{a=0}^{g-1} h^(s)_{gj+a}` oraz opisem sumowania i decymacji. Wprost stwierdza zmianę obserwabli i stały odstęp fizyczny `1/W`. Przy `T=W/s`, częstotliwość koszyka to `k/(Ts)=k/W`; zmienia się zakres Nyquista. Wniosek o ograniczonej porównywalności luk przy różnych szerokościach pozostaje w `main.tex:180`. | Brak. Dodatkowy wykład o aliasingu nie jest warunkiem odziedziczonego kryterium. |

## Wierność nowego rysunku

Sprawdziłem wszystkie osiem skrótów SHA-256 wymienionych w `analysis/reviewed_spectrum_figure_manifest.json:2–10`: generator, PDF i sześć wejść są zgodne z manifestem. Średnie obserwowane z `spectral_summary.csv` odpowiadają średnim 80 wektorów kluczowych z `evaluation_spectra.npz`; średnie modeli odpowiadają `monte_carlo_spectra.npz`. Dla pokazanych widm DC wynosi zero, a suma AC wynosi jeden z dokładnością numeryczną. Generator wybiera `q_observed`, bez referencji (`make_reviewed_spectrum_figure.py:76–118`).

Przy `T=64` poprawnie łączy `q[k]+q[64-k]` dla `k=1,…,31` i zachowuje samo `q[32]` dla Nyquista (`make_reviewed_spectrum_figure.py:48–60`). Oś `k/16` cykli na blok daje `1/512` cykli/bit dla `k=16` i `2/512` dla `k=32` (`make_reviewed_spectrum_figure.py:132–149`). W obrębie pasma dla `s=128` widoczne są więc składowa podstawowa i druga harmoniczna, a także tło; niczego poza tym pasmem podpis nie obiecuje.

Kontrola liczb dla pokazanych paneli:

| Szyfr, `s=128` | L1 M0 | L1 M1 |
| --- | ---: | ---: |
| ChaCha20/2 | 0,32198880594 | 0,08435559478 |
| Salsa20/2 | 0,10100110417 | 0,01042818754 |

Te wartości odtworzyłem ze średnich zapisanych w NPZ, bez używania funkcji generatora; zgadzają się z `spectral_errors.csv:6–7,12–13`. Składanie zachowuje również pełną dwustronną odległość. Analogiczna kontrola potwierdziła wszystkie 12 odległości dla dwóch modeli, dwóch szyfrów i trzech szerokości.

**Przedziały zostały złożone poprawnie.** W każdym zapisanym kluczu widmo rzeczywistej trajektorii jest symetryczne; największa różnica par sprzężonych dla pokazanych danych wynosiła `3,47e-18`. W konsekwencji każdy resampling całych kluczy zachowuje tę symetrię, a kwantyle złożonej pary są dwukrotnością odpowiednich kwantyli jednego koszyka. Odtworzenie istniejących 5000 losowań bootstrapowych z zapisanym ziarnem i liczenie kwantyli bezpośrednio po złożeniu dało zgodność z granicami użytymi w rysunku do `3,33e-16`. Nyquist pozostał liczony pojedynczo. Pasmo dotyczy obserwacji; generator nie przedstawia przedziałów predykcyjnych modeli, zgodnie z `main.tex:123` i manifestem (`:19–20`). Nie jest to pasmo jednoczesne dla całego widma.

Dodatkowo odtworzyłem pomiar z surowych HW dla pierwszego i ostatniego klucza ewaluacyjnego, 1200 i 1279, wszystkich masek i trzech szerokości. Niezależna realizacja przez rFFT, uśrednienie mocy bazowych, normalizację na maskę i średnią po maskach zgodziła się z zapisanymi profilami do `5,55e-17`. To ograniczona kontrola przekształcenia danych, nie ponowne sprawdzenie całego generatora szyfrów.

Ogląd istniejącego PDF potwierdza czytelne legendy, oznaczenia częstotliwości i skalę logarytmiczną. Dolne panele zachowują rozróżnienie surowej pochodnej słowa bez feed-forward oraz kontrastu fundamentalnej mocy przy add; podpis nie utożsamia tych map.

## Spójność wniosków o modelach

Twierdzenia `main.tex:188` zgadzają się z `compact_summary.csv:2–25` i `spectral_errors.csv:2–13`: oba modele mają zgodny z obserwacją znak wszystkich sześciu luk; M1 ma mniejsze błędy L1 i mniejsze bezwzględne błędy `Delta F512` we wszystkich sześciu ustawieniach; M0 jest bliższy wszystkim trzem lukom ChaCha20, a M1 wszystkim trzem lukom Salsa20. Abstrakt (`main.tex:22`) zachowuje ten rozdział, pisząc o poprawie średnich widm, lecz nie każdej luki entropii. Nie znalazłem rozszerzenia tego wyniku do przewagi detektora ani do dowodu poprawności całego modelu.

Kontrola uzupełniająca dla **N8** potwierdza dodany reprezentatywny przykład: wiersz M1/Salsa20/128/G (`compact_summary.csv:25`) ma MCSE `0,000380826547` bitów oraz błąd obserwacja minus prognoza `0,006670685113` bitów. MCSE odtworzony z 4096 już zapisanych wartości jest zgodny z tabelą; `main.tex:188` zaokrągla je poprawnie do 0,00038 i 0,00667. `main.tex:123` odróżnia to źródło niepewności od resamplingu kluczy ewaluacyjnych przy ustalonym dopasowaniu i estymacie MC. W zakresie tej kontrolowanej liczby kryterium N8 również jest **addressed**; nie oceniam tu pozostałych zadań recenzenta statystycznego.

## Nowe obserwacje i wymagane działania

**Nowe defekty: brak stwierdzonych w sprawdzonym zakresie.** M1 nadal nie odtwarza każdego szczegółu tła, a uśrednianie może kompensować błędy masek. To znane granice jawnie podane w `main.tex:123,188`, nie nowy zarzut i nie powód do wymagania kolejnej kohorty.

Poprzednia opinia specjalistyczna proponowała również liczbową tabelę rozkładu DC/AC. Nie ma jej w odziedziczonym zbiorze warunków domknięcia; nie przywracam tej propozycji jako nowego obowiązku. Minimalny zakres naprawy dla N5–N7 został wykonany. Ta opinia nie rozstrzyga N1–N4 ani N9 i nie stanowi samodzielnej decyzji redakcyjnej o całym artykule.
