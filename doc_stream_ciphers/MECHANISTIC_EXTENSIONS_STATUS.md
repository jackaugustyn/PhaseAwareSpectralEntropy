# Trzy rozszerzenia merytoryczne — v0.18.0

Data: 31 października 2026. Wszystkie trzy zadania wykonano i włączono
do artykułu. Główny tekst zachowuje oś **funkcja rundowa → feed-forward
→ mierzona odpowiedź**. PDF ma 20 stron i 40 pozycji bibliograficznych;
samodzielny suplement ma 7 stron i 11 pozycji.

## 1. Twierdzenie o warunkowej randze i średniej HW

Dla `f_C(u)=((u XOR C)+u) mod 2^n` część liniowa ma rangę równą liczbie
zer w bitach 0–n−2 stałej C. Średnia HW odpowiedzi na wszystkie n zmian
jednobitowych wynosi `max(n−1−t(C),0)/n`, gdzie t(C) liczy kolejne jedynki
od najmłodszego bitu. Dowód wykorzystuje rozłączne przedziały przeniesień.

W Salsa20/2 dotyczy to wyjściowego słowa 7, zmienianego drugiego słowa
nonce i ustalonego pozostałego stanu. Średnia jest ograniczona przez
31/32 zmienionego bitu. Przykłady algebraiczne C=0 i C=0xfffffffe mają
identyczną średnią, lecz rangi 31 i 1. Nie są przedstawiane jako próbki
zaobserwowane w szyfrze; nie przypisujemy tej rangi całemu szyfrowi.

Wniosek znajduje się w `arx_affine_corollary.tex`, pełny dowód w S5
suplementu (`arx_affine_proof.tex`). Audyt w
`data/arx_affine_corollary/` sprawdził 87 380 wyczerpujących przypadków
małych słów, 168 960 zachowanych kontekstów C, eliminację dla 10 560
różnych stałych i 163 840 zapisanych kolumn pochodnych. Zero naruszeń.
Nie generowano nowej kohorty ani nowych wartości p.

## 2. Zamrożone modele przewidujące widmo

Protokół: `ARX_SPECTRAL_PREDICTION_PROTOCOL.txt`.
SHA-256: `358fad464030014909e176064436f2bd4c1a3c2d3af72fd5e4d86f827921b186`.

Trening wykorzystuje wyłącznie wcześniejsze obserwacje dwurundowe dla
80 par kluczy 840–919. M0 losuje niezależnie z globalnych rozkładów HW32
dla maski i pozycji słowa. M1 zachowuje profile warunkowe klucza i bazowego
nonce, a niezależnie losuje reszty pomiędzy słowami i blokami. Oba modele
są empiryczne; nie stanowią pełnej analitycznej teorii ARX.

Wykonano po 4096 symulowanych par kluczy. Parametry i predykcje zapisano
z hashami przed wygenerowaniem 80 nowych par kluczy 1200–1279. Każdy
wariant obejmuje wszystkie 64 maski, cztery bazy i 8192 bity, agregowane
do 32/64/128 bitów. Model i budżet nie były dostrajane do walidacji.

Oba modele odtwarzają zaobserwowane znaki G we wszystkich sześciu
ustawieniach. M1 zmniejsza błąd średniego widma AC i bezwzględny błąd
udziału mocy podstawowej we wszystkich sześciu ustawieniach. Przykładowo:

| Pomiar przy 128 bitach | Obserwacja | M0 | M1 |
| --- | ---: | ---: | ---: |
| ChaCha20 ΔF512 | 0,53850 | 0,42303 | 0,55252 |
| Salsa20 ΔF512 | 0,80082 | 0,76860 | 0,80452 |
| Salsa20 G, bity entropii | 0,80132 | 0,85574 | 0,79465 |

M0 jest jednak bliższy wartościom G dla wszystkich trzech szerokości
ChaCha20; M1 poprawia G dla Salsa20. Nie wybrano jednego modelu jako
ogólnie najlepszego. Przedziały dla średnich błędów są warunkowe względem
ustalonego dopasowania i estymaty Monte Carlo; MCSE podano oddzielnie.
L1 porównuje średnie widma AC i może ukrywać kompensację błędów masek.
Jego dodatnia dolna granica nie jest testem odrzucenia modelu.

Wyniki i pełne osie: `data/arx_spectral_prediction/README.md`.
Niezależny audyt odtworzył wszystkie symulacje oraz 16 640 bloków szyfrów
dla kluczy 1200 i 1279, parametry modeli, oczekiwane widma, statystyki,
przedziały i MCSE. Maksymalna różnica metryk wyniosła 8,88 × 10⁻¹⁶;
kontrole pochodzenia i rozdzielenia kohort przeszły.

## 3. Rzeczywista trzecia runda i punkt operacyjny

Protokół: `ARX_ROUND_TRANSITION_PROTOCOL.txt`.
SHA-256: `88a8b1812f32af7904c6a5b656350a047bac87804ca7209a551ae99360a6f6b1`.

Nowy evaluator wykonuje pojedyncze rundy, z kontrolą względem niezależnej
implementacji skalarnej i wcześniejszych wektorów dla rund parzystych.
Badanie obejmuje 80 nowych par kluczy 1400–1479, 2/3/4 rundy, trzy
finalizacje, 64 maski jednobitowe i wcześniej ustalony panel 38 par.
Trzy rundy są konstrukcją eksperymentalną; runda trzecia jest kolumnowa.

| Zaplanowany kontrast Salsa20, runda 3 minus 2 | Wynik [95% CI] | Holm p |
| --- | --- | --- |
| T1: skorygowana o kontrolę HW pochodnej wewnątrz x7, słowo 7 bez feed-forward | +15,81934 [15,72011; 15,92031] zmienionego bitu | 0,000020 |
| T2: skorygowany o kontrolę udział mocy F512, dodawanie, segmenty 128-bitowe | −0,52287 [−0,52559; −0,52020] | 0,000020 |

Oba testy tworzą jedną rodzinę Holma; wartości p osiągają rozdzielczość
100 000 symulacji zmian znaków. Przed aktualizacją `c=w7` w quarter-round
(15,3,7,11) wszystkie 10 240 zapisanych pochodnych były zerowe, a po
aktualizacji wszystkie niezerowe. Dotyczy to dwóch ustalonych par masek
wewnątrz drugiego słowa nonce. Surowa średnia HW przy trzech rundach
wynosi 15,84033, przy zachowanym małym opisowym deficycie wobec kontroli.

Jednocześnie ΔF512 przy 128-bitowej segmentacji wynosi 0,80054, 0,27767
i 0,00041 dla 2/3/4 rund. **Utrata lokalnej afiniczności nie oznacza
jednoczesnego zaniku struktury całego bloku.** Pozostałe kontrasty,
w tym zmiany J i porównania ChaCha20, są opisowe.

Dane: `data/arx_round_transition/`. Niezależny audyt odtworzył 26 368
bloków szyfrów przez cztery pojedyncze rundy i 79 104 bloki referencji;
sprawdził pełne siedem rodzin tabel, przedziały i testy. Maksymalna
różnica numeryczna wyniosła 1,78 × 10⁻¹⁴. Zero naruszeń niezmienników.

## Integracja i kontrola

- Dodano trzy rozszerzenia do wkładu pracy, metod, wyników, dyskusji,
  abstraktu i wniosków, a dowód do suplementu. Figura 3 pokazuje oba
  modele oraz odrębne przejścia lokalne i blokowe.
- `python3 run.py vectors`: **50 testów — PASS**.
- Audyty trzech rozszerzeń: **PASS**. Domyślne polecenia są tylko do odczytu.
- 481 wcześniejszych plików naukowych porównano z manifestem v0.17.0:
  identyczne rozmiary i SHA-256. Bibliografii i wcześniejszych wyników
  nie zmieniono. Zachowano nierozstrzygający wynik E3 ChaCha20 (p = 0,108).
- Artykuł i suplement kompilują się niezależnie. Przejrzano wzory,
  nową tabelę, figurę oraz końcowe wpisy bibliografii.
- Przygotowane archiwa v0.18.0 zawierają nowe protokoły, źródła,
  checkpointy, wyniki i audyty. Rekord nie został publicznie zdeponowany.

Reprodukcję obliczeń i dokładne polecenia opisują pliki README poszczególnych
nowych zbiorów. `run.py audits` sprawdza także wcześniejsze badania;
bieżąca kontrola zachowania starszych plików opiera się na ich hashach,
bez ponownego generowania wcześniejszych kohort. Wnioski nie ustanawiają
ataku, słabości pełnorundowej ani przewagi detekcyjnej nowej miary.
