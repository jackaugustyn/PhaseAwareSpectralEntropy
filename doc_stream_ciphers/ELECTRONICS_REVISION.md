# Przebudowa pod MDPI Electronics — v0.14.0

Data wersji: 29 października 2026.

Ten dokument opisuje historyczną przebudowę v0.14.0. Następne rozszerzenie
v0.15.0, nowe wyniki i aktualny stan walidacji opisano w
`RESEARCH_EXTENSION_STATUS.md`; bieżący PDF ma 19 stron.

Tytuł: **Block-Position Structure in Reduced ChaCha20 and Salsa20: Experimental Diagnostics of IV Diffusion**.

## Kierunek i wykonane zmiany

Artykuł przedstawia eksperymentalną diagnostykę dyfuzji IV/nonce w zredukowanych rdzeniach ARX. Entropia widmowa pozostaje narzędziem analizy, a uzasadnienie wkładu opiera się na zmierzonej strukturze i kontrolowanych eksperymentach.

1. Tytuł, abstrakt, wstęp, dyskusja i wnioski koncentrują się na trzech rezultatach: czteropozycyjnej strukturze, interwencji rotacyjnej i niezależnym skanie wszystkich 64 bitów nonce.
2. Główne wyniki rozpoczynają się od struktury ChaCha20/2 i Salsa20/2. Szerokie porównanie siedmiu szyfrów, Grain/Trivium oraz A5/1 przeniesiono do dodatków A–C z zachowaniem protokołów, liczb i rodzin testów.
3. Panel (a) ryciny przedstawia teraz bezpośrednie profile czterech pozycji HW i dopasowane kontrole. Panele (a,b) pochodzą z jednej kohorty matched nonce, a panel (c) z odrębnej kohorty pełnego skanu. Wykorzystano istniejące średnie i przedziały; nie wykonano nowych eksperymentów.
4. Porównanie z prostymi miarami jest elementem głównego wywodu. Tekst wyjaśnia, co wnosi dekompozycja DC/AC, bez deklarowania przewagi w mocy detekcji.
5. Wyjaśniono, że „phase-aware” dotyczy wyrównania pozycji próbek, a nie estymacji fazy zespolonych współczynników Fouriera.
6. Poprawiono interpretację ChaCha20: bliski zeru gap entropii współwystępuje z kompensującymi się odpowiedziami HW słów wyjściowych. Liniowa kompensacja HW nie jest dowodem przyczyny zmiany nieliniowej entropii.
7. Opcję lokalnej klasy MDPI zmieniono na `electronics`. Zsynchronizowano README, metadane i skrypty pakowania; przygotowano projekt cover letter.

## Zachowane główne wyniki

| Wynik | Wartość i zakres interpretacji | Źródło |
| --- | --- | --- |
| Czteropozycyjny rozstęp HW | Początkowe kohorty: 18.35 i 30.23 bitu nadwyżki względem kontroli; osobna kohorta matched nonce: 17.87 i 30.41. | `unified_six_phase_summary.csv`, `salsa20_transfer_phase_summary.csv`, `same_data_benchmark_summary.csv` |
| Rotacje | Redukcja bezwzględnego średniego kontrastu AC o 95.8793% i 94.1716%; nie jest to procent wyjaśnionego braku dyfuzji ani marginesu bezpieczeństwa. | `matched_nonce_phase_summary.csv` |
| Salsa20/2, drugie minus pierwsze słowo nonce | +0.79059 bitu; CI [0.78404, 0.79729]; Holm p = 2 × 10⁻⁵, na granicy rozdzielczości symulowanego testu. | `arx_planned_tests.csv` |

Wszystkie źródłowe CSV znajdują się w odpowiednich podkatalogach `doc_stream_ciphers/data/`. Nie zmieniono danych surowych, wyników statystycznych ani zablokowanych protokołów.

## Walidacja wydania

- `latexmk -pdf -interaction=nonstopmode -halt-on-error -silent main.tex`: kompilacja zakończona poprawnie; PDF ma 15 stron. Log nie zawiera ostrzeżeń kompilacji, przepełnień ani brakujących odsyłaczy i cytowań.
- Obejrzano render całego dokumentu oraz powiększenia pierwszej strony i ryciny z tabelą głównego kontrastu. Sprawdzono numerację dodatków A–C i tabel A1–A3, dane autora, tytuł i nazwę Electronics.
- `python3 run.py vectors`: 16 sprawdzeń wektorów i niezmienników zakończonych powodzeniem.
- `python3 run.py audits`: wszystkie sześć audytów zakończonych powodzeniem, w tym porównanie danych surowych z podsumowaniami, rotacje, benchmark na tych samych strumieniach oraz hashe protokołów i wyników follow-up.
- Dodatkowa kontrola ryciny: średnie i granice przedziałów panelu (a) odtworzone z archiwalnych tablic raw zgadzają się z wykorzystanym CSV do `1e-12`.
- `git diff --check`: bez błędów. Dane w `data/`, `analysis/` i ustalone protokoły nie mają zmian względem wersji wejściowej.
- `python3 run.py package` buduje oba archiwa v0.14.0 z kontrolą CRC, listy plików i SHA-256 oraz odświeża manifest folderu. Wypakowany reviewer ZIP obsługuje `python3 verify_package.py` dzięki odczytowi dołączonego `SHA256SUMS.json`.

## Stan przed zgłoszeniem

Przygotowano lokalne materiały do oceny autora; niczego nie przesłano do czasopisma ani repozytorium publicznego. Nie ma przypisanego DOI ani wybranej licencji publicznego depozytu. Cover letter pozostaje projektem, ponieważ nie potwierdzano bieżącego statusu równoległych zgłoszeń.

Lokalny szablon MDPI obsługuje Electronics. Bieżących instrukcji internetowych czasopisma nie udało się zweryfikować: próba odczytu oficjalnej strony zakończyła się błędem DNS. Przebudowa odpowiada przekazanym wytycznym redakcyjnym; nie stanowi potwierdzenia kompletu aktualnych wymogów administracyjnych czasopisma.
