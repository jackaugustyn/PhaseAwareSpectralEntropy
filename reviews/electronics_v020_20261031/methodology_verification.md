# Weryfikacja metodologii i statystyki — v0.20

31 października 2026 r.; docelowe czasopismo: Electronics.

**Wynik:** odziedziczone uwagi N4 i N8 zostały usunięte. Nowy opis ogranicza interpretację testów zgodnie z ich założeniami, a przykład MCSE odpowiada zachowanym wynikom symulacji. N3 jest spełnione w zakresie przygotowanego, identyfikowalnego pakietu recenzenckiego. Nie stwierdziłem nowej istotnej usterki metodologicznej ani statystycznej wynikającej ze skrócenia artykułu. W sprawdzonym zakresie nie jest potrzebna dalsza poprawka, nowa kohorta ani dodatkowy manuskrypt.

Jest to opinia doradcza, nie zwalidowany panel ARS ani decyzja redakcji. Kalibracja trafności tej opinii jest nieznana (`NOT_CALIBRATED`); nie szacuję prawdopodobieństwa przyjęcia. Najpierw przeczytałem [odziedziczone kryteria](inherited_criteria.md) i [poprzednią opinię metodologiczną](../electronics_v019_20261031/methodology_advisory.md), następnie bieżący `main.tex` z oboma plikami `input`, starszą wersję oraz wybrane źródła i dane. Nie otwierałem `REVIEW_RESPONSE_V020.md` ani opinii innych recenzentów tej rundy. Podczas sprawdzania pakietu widziałem jego metadane, w tym autorski opis zmian; nie deklaruję pełnej ślepoty na rewizję ani niezależnych procesów błędów między czytelnikami.

## Odziedziczone kryteria w zakresie tej opinii

| Kryterium | Ocena | Weryfikacja i minimalne dalsze działanie |
| --- | --- | --- |
| N4 — hipoteza i założenia testu zmian znaków | **addressed** | [Metody, w. 105–107](../../doc_stream_ciphers/main.tex:105) podają hipotezę zerowej średniej, wartość bezwzględną średniej jako statystykę, niezależne znaki na poziomie klucza, poprawkę plus-one oraz warunek niezmienniczości rozkładu pod hipotezą zerową. Jawnie wskazano, że zerowa średnia i sprzężenie z odniesieniem nie wystarczają, a wartości p są warunkowane założeniami. Nie potrzeba dalszej poprawki do zamknięcia N4. |
| N8 — błąd Monte Carlo i niepewność ewaluacji | **addressed** | [Metody, w. 123](../../doc_stream_ciphers/main.tex:123) oddzielają MCSE od przedziałów opartych na kluczach ewaluacyjnych. [Wyniki, w. 188](../../doc_stream_ciphers/main.tex:188) podają reprezentatywne 0,00038 bitu wobec błędu 0,00667 bitu; [Data Availability, w. 210](../../doc_stream_ciphers/main.tex:210) wskazuje dokładny CSV. Liczby sprawdzono także na zapisanych wynikach MC. Nie ma potrzeby dodawania kolejnej tabeli do artykułu ani suplementu. |
| N3 — identyfikowalny pakiet dowodowy | **addressed**, w zakresie lokalnego pakietu | [Data Availability, w. 210](../../doc_stream_ciphers/main.tex:210) wskazuje `iv_diffusion_research_review_v0.20.0.zip`, wersję, manifest i instrukcje reprodukcji. [Pakiet](../../doc_stream_ciphers/iv_diffusion_research_review_v0.20.0.zip) istnieje i zawiera wskazane materiały. Manuskrypt i `compact_summary.csv` są w nim identyczne bajtowo z ocenianymi plikami. Nie potwierdzam przesłania do systemu czasopisma ani publicznej dostępności; tekst nie twierdzi, że pakiet publicznie zdeponowano. |
| N5 — definicja odległości widmowej | **addressed**, kontrola pomocnicza | [W. 123](../../doc_stream_ciphers/main.tex:123) określa kolejność: średnia mocy czterech baz, normalizacja AC w kluczu i masce, uśrednienie masek i kluczy, a następnie norma L1; zakres 0–2 i brak odejmowania widma odniesienia są jawne. Odpowiada to [obliczaniu widm, w. 129–139](../../experiments/stream_rounds_study/arx_spectral_prediction.py:129) i [odległości, w. 407–413](../../experiments/stream_rounds_study/arx_spectral_prediction.py:407). |
| N7 — szerokość segmentu a rozdzielczość częstotliwości | **addressed**, kontrola pomocnicza | [W. 60](../../doc_stream_ciphers/main.tex:60) opisuje sumowanie sąsiednich HW i decymację oraz odstęp częstotliwości 1/W. Zgadza się to z [agregacją w kodzie, w. 157–167](../../experiments/stream_rounds_study/arx_resolution_validation.py:157). Nie znaleziono regresji w definicji obserwowanej wielkości. |

N1, N6 i N9 nie otrzymują w tej opinii rozstrzygnięcia: nie wykonywałem porównania z pełnymi tekstami najbliższych prac, pełnego audytu nowej figury ani niezależnej weryfikacji dowodu algebraicznego. Są **unverifiable w zakresie wykonanych tu kontroli**, co nie jest stwierdzeniem ich niespełnienia przez artykuł. W N2 sprawdziłem zakres sformułowań, opisany poniżej, bez ponownego generowania świadków.

## Zgodność inferencji z kodem i danymi

Implementacja [testu, w. 181–195](../../experiments/stream_rounds_study/arx_resolution_validation.py:181) przyjmuje macierz klucz × punkt końcowy, oblicza `abs(mean)` i mnoży wszystkie punkty danego klucza przez ten sam znak. Porównuje statystyki dwustronnie i zwraca `(extremes+1)/(replicates+1)`. Tolerancja numeryczna `1e-12 * max(1, abs(mean))` jest technicznym szczegółem porównania, nie odmiennym testem od opisanego. [Feed-forward, w. 474–490](../../experiments/stream_rounds_study/arx_feedforward_study.py:474) i [przejście rund, w. 435–452](../../experiments/stream_rounds_study/arx_round_transition.py:435) tworzą sparowane kontrasty na poziomie klucza i wywołują tę funkcję. Osobny [test rotacji, w. 238–270](../../experiments/stream_rounds_study/matched_nonce_phase_study.py:238) również odwraca znaki całych kluczy i stosuje plus-one.

Tekst nie przedstawia teraz tych procedur jako dokładnych testów samej hipotezy zerowej średniej bez dodatkowych założeń. Takie ograniczenie jest wystarczającą odpowiedzią na pierwotną uwagę N4. Nie udowodniono ani nie sprawdzono tu rzeczywistej niezmienniczości rozkładu każdego kontrastu względem znaków; to zachowana granica inferencji, nie nowy warunek zamknięcia uwagi. Podobnie zastrzeżenie „conditional on valid endpoint calibration” przy korekcie Holma prawidłowo wyklucza traktowanie korekty wielokrotności jako naprawy niekalibrowanych wartości wejściowych.

Przeliczyłem korektę Holma z zachowanych wartości p, bez ponownego losowania znaków:

| Rodzina | Liczba testów | Sprawdzony zapis |
| --- | --- | --- |
| Pełny skan | 2 | [arx_planned_tests.csv, w. 2](../../doc_stream_ciphers/data/literature_mask_followup/arx_planned_tests.csv:2) |
| Feed-forward | 4 | [arx_feedforward_planned_tests.csv, w. 2](../../doc_stream_ciphers/data/arx_feedforward_results/arx_feedforward_planned_tests.csv:2) |
| Przejście rund | 2 | [arx_round_transition_planned_tests.csv, w. 2](../../doc_stream_ciphers/data/arx_round_transition/arx_round_transition_planned_tests.csv:2) |
| Rozdzielczość | 5 | [arx_resolution_validation_planned_tests.csv, w. 2](../../doc_stream_ciphers/data/arx_resolution_validation/arx_resolution_validation_planned_tests.csv:2) |
| Rotacja | 2 | [matched_nonce_phase_planned_tests.csv, w. 2](../../doc_stream_ciphers/data/matched_nonce_phase_results/matched_nonce_phase_planned_tests.csv:2) |

Wszystkie pięć rodzin dało dokładną zgodność korekty. W trzech plikach zawierających licznik ekstremów również przeliczenie plus-one dało dokładną zgodność. Zachowano 80 kluczy w każdym teście. Zaokrąglone wartości w [tabeli głównej](../../doc_stream_ciphers/main.tex:149), [wynikach rotacji](../../doc_stream_ciphers/main.tex:176) i [walidacji szerokości](../../doc_stream_ciphers/main.tex:180) odpowiadają tym plikom, w tym nierozstrzygnięty kontrast ChaCha20 `p=0,108`. Nie zmieniono liczebności rodzin względem v0.19; nie ma deklaracji wspólnej kontroli błędu dla wszystkich twierdzeń artykułu.

Resampling nie zamienia masek, baz ani bloków w niezależne replikacje: [w. 105](../../doc_stream_ciphers/main.tex:105) utrzymuje całą parę kluczy razem. [W. 113](../../doc_stream_ciphers/main.tex:113) nadal zastrzega, że 16 bloków M1 nie jest 16 niezależnymi jednostkami treningowymi; [w. 200](../../doc_stream_ciphers/main.tex:200) wyklucza powiększanie kohort przez symulacje i sprawdzenia deterministyczne.

## Weryfikacja przykładu MCSE

W [compact_summary.csv, w. 25](../../doc_stream_ciphers/data/arx_spectral_prediction/compact_summary.csv:25), dla M1/Salsa20/128/G, zapisano:

- predykcję 0,7946508248298033 bitu;
- MCSE 0,0003808265472147277 bitu;
- obserwację 0,8013215099431321 bitu;
- błąd obserwacja minus predykcja 0,0066706851133288 bitu.

Odczyt istniejącego `monte_carlo_metrics.npz` i obliczenie średniej oraz `SD(ddof=1)/sqrt(4096)` odtworzyły wszystkie 24 wiersze kompaktowej tabeli: największe różnice wyniosły około 1,55 × 10⁻¹⁵ dla predykcji i 4,88 × 10⁻¹⁹ dla MCSE. Odpowiada to [kodowi, w. 395–403](../../experiments/stream_rounds_study/arx_spectral_prediction.py:395). Nie była to nowa symulacja. Hash pliku MC zgadza się z manifestem zamrożonych predykcji, hash CSV z manifestem analizy, a manifest generacji ewaluacyjnej wskazuje bieżący hash manifestu predykcji.

Przedziały ewaluacyjne nadal warunkują na ustalonym dopasowaniu i oszacowaniu MC; nie propagują niepewności treningu. Zostało to jawnie zachowane w [w. 123](../../doc_stream_ciphers/main.tex:123) i [README, w. 69–80](../../doc_stream_ciphers/data/arx_spectral_prediction/README.md:69). Porównanie MCSE z błędem jest opisem dwóch skal, nie testem odrzucenia modelu. Nie wymagano wcześniej takiego testu ani pełnej propagacji niepewności i nie dodaję tego wymogu teraz.

## Regresje i nowe usterki

**Nie stwierdziłem nowej istotnej usterki w ocenianym zakresie.**

Rozdzielenie obiektów w N2 jest teraz wyraźne: [abstrakt](../../doc_stream_ciphers/main.tex:22), [przejście rund, w. 170–172](../../doc_stream_ciphers/main.tex:170) i [konkluzja](../../doc_stream_ciphers/main.tex:204) odnoszą utratę afiniczności do mapy słowa 7 przed finalizacją, a utrzymujące się widmo do standardowego wyjścia add. W. 170 wprost wyklucza wnioskowanie o afiniczności po dodawaniu modularnym z samego niezerowego świadka rdzenia. Nie pojawiła się nowa nadmierna interpretacja statystyczna tego wyniku.

Porównanie [części pobocznej v0.19, w. 233–237](../electronics_v019_20261031/manuscript.tex:233) z [v0.20, w. 194–198](../../doc_stream_ciphers/main.tex:194) pokazuje skrócenie opisu przy zachowaniu liczebności, efektów, przedziałów, 12- i 44-elementowych rodzin, liczby losowań i zastrzeżenia o nieodtworzonych warunkach kluczowych ataku na Trivium. Usunięto część szczegółów konfiguracji z głównego tekstu, ale nie zastąpiono wyniku nierozstrzygniętego dowodem równoważności ani spokojnego diagnostyku twierdzeniem o bezpieczeństwie. [W. 192](../../doc_stream_ciphers/main.tex:192) nadal wyklucza przewagę skalibrowanej mocy detekcji i równoczesną równoważność. To nie uzasadnia nowego warunku publikacji.

## Granice wykonanych sprawdzeń

Sprawdziłem wybrane funkcje i zachowane wyniki, poprawki arytmetyczne, zależności hashy oraz zawartość konkretnych pozycji archiwum. Dla `README.md`, `main.tex`, wskazanego CSV i protokołu predykcji sprawdziłem także zgodność hashy i rozmiarów z `SHA256SUMS.json`. Nie audytowałem ponownie całego archiwum, nie uruchamiałem pełnych eksperymentów ani bootstrapów, nie sprawdzałem transmisji do czasopisma i nie weryfikowałem niezależnego publicznego znacznika czasu zamrożenia. [Protokół, w. 3–7](../../doc_stream_ciphers/ARX_SPECTRAL_PREDICTION_PROTOCOL.txt:3) nadal uczciwie nazywa projekt lokalnie ustalonym rozszerzeniem, bez publicznej prerejestracji. Zachowane ograniczenia nie uniemożliwiają zamknięcia N3, N4 i N8 według przekazanych kryteriów.
