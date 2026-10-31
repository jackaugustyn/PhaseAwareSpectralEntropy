# Kondensacja artykułu — v0.17.0

Data: 30 października 2026. Zmiany dotyczą redakcji i organizacji materiału;
nie przeprowadzono nowych eksperymentów ani nie zmieniono wyników.

## Główna oś argumentacji

**Funkcja rundowa → feed-forward → mierzona odpowiedź nonce.**

1. **Funkcja rundowa:** powtarzalna struktura odpowiedzi zależna od pozycji
   w bloku; ścieżki zależności Salsa20/2 wyjaśniają niezmieniane słowa.
2. **Feed-forward:** kontrolowana zmiana finalizacji rozdziela asymetrię
   obecną w rdzeniu od wpływu dodawania modularnego; mieszane pochodne
   ujawniają interakcję zależną od obu słów nonce.
3. **Pomiar:** rotacje próbek oraz zmiany segmentacji pokazują, które cechy
   porządku i agregacji odpowiadają za obserwowany kontrast widmowy.

Taki porządek wprowadzono do abstraktu, wkładu pracy, wyników i dyskusji.
Sekcja wyników prowadzi kolejno przez funkcję rundową, feed-forward,
kolejność próbek, agregację oraz bezpośrednie diagnostyki i ograniczenia
wnioskowania dla większej liczby rund.

## Zakres skrócenia

- Główny PDF: **28 → 16 stron**, przy zachowaniu 40 pozycji bibliograficznych.
- Osobny suplement: **6 stron**, z 11 pozycjami bibliograficznymi przywołanymi
  w jego treści; są to pozycje z dotychczasowej bibliografii.
- Łącznie oba dokumenty mają 22 strony wobec wcześniejszych 28. Część
  skrócenia głównego tekstu wynika z przeniesienia materiału do suplementu.
- Przegląd literatury skrócono z około 2600 do około 700 słów, zachowując
  wszystkie 31 kluczy cytowań użytych w tej części. Usunięto rozbudowane
  zestawienie historycznych złożoności ataków; pozostawiono zwartą tabelę
  pokazującą związek istniejących metod z wkładem tej pracy.
- Skrócono powtórzenia w metodach, podpisach, dyskusji i wnioskach.
  Zachowano równania mechanizmu, definicje estymatorów, jednostki,
  liczebności kohort, rodziny testów oraz ograniczenia interpretacji.
- List przewodni przedstawia tę samą oś argumentacji.

## Materiał przeniesiony do suplementu

| Obecne miejsce | Zachowany materiał |
| --- | --- |
| S1; tabele S1–S2 | Wspólny protokół i kontekst siedmiu szyfrów, wcześniej dodatek A. |
| S2; tabela S3 | Badania lokalności Grain/Trivium, wcześniej dodatek B. |
| S3 | Eksperymenty A5/1, wcześniej dodatek C. |
| S4; tabela S4 | Zestawienie efektów w zredukowanych rdzeniach ARX, wcześniej tabela `tab:reduced`. |
| S4; tabela S5 | Pełne zestawienie luk dla trzech wariantów feed-forward, wcześniej tabela `tab:ffgaps`. |

Wnętrza wszystkich pięciu tabel zachowano bez zmian. Suplement zawiera
własne definicje pomiaru i wnioskowania, bibliografię oraz odsyłacze;
kompiluje się niezależnie od plików pomocniczych głównego artykułu.

## Zachowane rozstrzygnięcia i ograniczenia

W głównym tekście pozostały pierwotna luka Salsa20/2 +0,79059 bitu,
eksperyment rotacyjny, niezależna walidacja segmentacji oraz komplet czterech
zaplanowanych testów feed-forward. Zachowano nierozstrzygający wynik
ChaCha20 przy 128-bitowej agregacji (skorygowane p = 0,108).

Entropia widmowa opisuje profile HW odpowiedzi pierwszego rzędu. Mieszane
pochodne drugiego rzędu są osobnym pomiarem HW, którego jednostką są
zmienione bity na 32-bitowe słowo. Warunkowa afiniczność Salsa20/2 dotyczy
jednego słowa nonce przy ustalonej wartości zależnej od drugiego słowa.
Równość pochodnych wariantów bez feed-forward i z XOR pozostaje dokładnym
faktem algebraicznym, oddzielonym od wnioskowania statystycznego.

Praca nie wykazuje przewagi detekcyjnej nowej miary, nie przedstawia nowego
ataku i nie dowodzi słabości pełnorundowych szyfrów. Pełna bibliografia,
figury, dane, protokoły i kod naukowy pozostają zachowane. Wersja sprzed
kondensacji jest dostępna w archiwach v0.16.0.

## Kontrola redakcyjna i odtwarzanie

- Główny tekst i suplement skompilowano bez ostrzeżeń, przepełnień i
  brakujących odsyłaczy; sprawdzono także wygląd stron i kompletność
  ostatnich pozycji bibliografii.
- Porównano cytowania i zawartość przeniesionych tabel z wydaniem v0.16.0.
- Wszystkie 481 plików naukowych objętych porównaniem z manifestem v0.16.0
  zachowują identyczne SHA-256 i rozmiary: dane, analizy, kod eksperymentów,
  testy i narzędzia naukowe, protokoły, obie figury oraz bibliografia.
- Zaktualizowano `run.py build`, aby niezależnie kompilował oba dokumenty.
- Oba archiwa v0.17.0 obejmują źródła i PDF suplementu; archiwum badawcze
  zawiera ponadto ten opis zmian.
- Testów szyfrów i audytów numerycznych z wydania v0.16.0 nie powtarzano
  na potrzeby zmian redakcyjnych. Ich wyniki dokumentują wcześniejsze
  raporty; zgodność zachowanych plików można sprawdzić za pomocą manifestów
  SHA-256 obu wydań.
