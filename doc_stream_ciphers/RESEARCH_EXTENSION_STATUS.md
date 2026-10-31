# Wzmocnienie artykułu: literatura, mechanizm i odporność pomiaru

Data rozpoczęcia: 29 października 2026.

Ten raport dokumentuje rozszerzenie v0.15.0. Dalsze doświadczenia feed-forward i masek krzyżowych opisuje `FEEDFORWARD_EXTENSION_STATUS.md` (v0.16.0). Liczba stron i wyniki weryfikacji poniżej dotyczą historycznego wydania v0.15.0.

## Zakres

1. Porównanie wkładu z najbliższymi dostępnymi źródłami, bez nieuzasadnionej deklaracji pierwszeństwa.
2. Powiązanie profili wyjściowych z zależnościami operacji w dwóch rundach i modularnym feed-forward.
3. Analiza segmentów 32/64/128 bit i okien wyjścia; potwierdzenie wybranych przewidywań na odrębnej kohorcie.

## Stan prac

- Porównanie z już cytowaną literaturą: wykonane w `related_work_comparison.tex`; granice dostępu do źródeł opisano w `RELATED_WORK_NOTES.md`.
- Mechanizm: wykonana analiza i kontrola archiwum w `arx_mechanism_analysis.py`; wyniki w `data/arx_mechanism_results/`.
- Wtórna analiza rozdzielczości i okien: wykonana dla 90 konfiguracji i 80 kluczy, wyniki w `data/arx_resolution_results/`. Jest opisowa, nie była zaplanowana przed oglądaniem pierwotnej kohorty.
- Walidacja na nowych kluczach: wykonana w całości. Protokół zapisano przed generacją w `ARX_RESOLUTION_VALIDATION_PROTOCOL.txt`, SHA-256 `01421b276761aa61f8ab69b1339e83c8a5492615d5fa5f3d632e844295a7032b`. Obejmuje 80 nowych par kluczy (840–919), dwie i cztery rundy, wszystkie 64 maski oraz 8192 bity wyjścia. Wyniki: `data/arx_resolution_validation/` — surowe tablice, 2880 rekordów per-key, 36 opisowych podsumowań, pięć zaplanowanych testów i checkpointy.
- Integracja tekstu: zakończona. Nowe podsekcje 1.1, 2.8–2.9, 3.4 i 3.7; tabele 1, 4 i 6; zaktualizowany abstrakt, wkład, dyskusja i wnioski. Zachowano wcześniejsze wyniki i odrębność ich rodzin testów.
- PDF: 19 stron; kompilacja `latexmk -pdf -interaction=nonstopmode -halt-on-error -silent main.tex` zakończona bez ostrzeżeń, przepełnień i brakujących odsyłaczy. Obejrzano render całości oraz powiększenia nowych tabel i wyprowadzenia.
- Wydanie v0.15.0 obejmuje rozszerzony zestaw źródeł, danych, testów i raportów. Skrypty pakowania sprawdzają listy plików, CRC oraz SHA-256; starsze archiwa pozostają wersjami historycznymi.

## Najważniejsze nowe ustalenia

- Czteropozycyjny opis wynika z obserwacji w segmentach 128-bitowych. Nadwyżka mocy częstotliwości 1/512 bitu pozostaje dodatnia także przy 32- i 64-bitowych segmentach oraz w obu połówkach wyjścia; struktura wiąże się z blokiem szyfru.
- Znak asymetrii Salsa20/2 pozostaje dodatni we wszystkich trzech rozdzielczościach. Świeże wyniki to +1.09903, +0.96249 i +0.79172 bitu dla segmentów 32, 64 i 128 bitów.
- ChaCha20/2: świeży kontrast wynosi +0.03382 bitu przy 32 bitach oraz −0.06129 przy 64 bitach. Mały kontrast +0.00596 przy 128 bitach ma opisowy przedział powyżej zera. Wcześniejszy wynik bliski zeru przy 128 bitach nie uzasadnia ogólnej symetrii słów nonce.
- Pięć zaplanowanych testów świeżej kohorty osiąga wspólny próg rozdzielczości symulacji po korekcie Holma: około 5 × 10⁻⁵. Oryginalny test Salsa20 +0.79059 z p = 2 × 10⁻⁵ pozostaje wynikiem wcześniejszej, odrębnej rodziny.
- Struktura rund Salsa20 przewiduje brak wpływu pierwszego słowa nonce na słowo wyjścia 1 oraz drugiego na słowa 0,1,2,3,6. Modularny feed-forward dodatkowo kasuje wpływ bitu 31 drugiego słowa nonce na słowo wyjścia 7. Wszystkie sprawdzenia tych równości i zależności od licznika przeszły na nowej kohorcie.

## Weryfikacja

- `python3 run.py vectors`: 26 sprawdzeń wektorów i niezmienników zakończonych powodzeniem, w tym 10 nowych kontroli agregacji i statystyki.
- `python3 run.py audits`: wszystkie wcześniejsze audyty oraz nowy `tools/audit_arx_extensions.py` zakończone powodzeniem.
- Niezależna implementacja z rFFT odtwarza 16 punktów końcowych w 36 ustawieniach dla 80 kluczy (maksymalna różnica 8.88 × 10⁻¹⁶), przedziały z 5000 bootstrapów (4.44 × 10⁻¹⁶), 100 000 replikacji sign-flip oraz korektę Holma. Raport: `data/arx_resolution_validation/independent_audit.json`.
- Źródła starych eksperymentów, ich surowe dane i ustalone protokoły nie zostały zmienione. Nowe analizy, protokół i dane przechowywane są oddzielnie.

## Aktualizacja literatury z 30 października 2026

Autor uzupełnił przegląd literatury i dodał 16 pozycji bibliograficznych. Bieżące `biblio.bib`, `related_work_comparison.tex` oraz `RELATED_WORK_NOTES.md` zawierają tę aktualizację i zakres weryfikacji źródeł. Wcześniejsze ograniczenie dostępu sieciowego opisywało stan v0.15.0; nie jest oceną obecnego przeglądu. Rozszerzenie feed-forward zachowuje zmiany autora.
