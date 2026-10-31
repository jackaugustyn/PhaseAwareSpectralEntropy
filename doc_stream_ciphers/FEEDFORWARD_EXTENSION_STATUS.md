# Feed-forward i maski krzyżowe — wydanie v0.16.0

Data: 30 października 2026. Badanie, analiza i integracja z artykułem zakończone.

Ten raport dokumentuje wydanie v0.16.0. Redakcyjną kondensację v0.17.0,
z 16-stronicowym artykułem i osobnym 6-stronicowym suplementem, opisuje
[CONDENSATION_NOTES.md](CONDENSATION_NOTES.md). Wyniki badania pozostają bez zmian.

## Wykonany zakres

- 80 nowych par kluczy: indeksy 1000–1079, nowy seed i domeny wyprowadzania.
- ChaCha20 i Salsa20 przy dwóch i czterech rundach; po cztery wspólne bazowe
  nonce i 8192 bity wyjścia, czyli 16 bloków na wierzchołek wejściowy.
- Trzy finalizacje tych samych stanów roboczych: standardowe dodawanie
  modularne, brak feed-forward i XOR feed-forward.
- Wszystkie 64 maski jednobitowe oraz 38 ustalonych par drugiego rzędu:
  32 krzyżowe o zgodnych przesunięciach bitowych, cztery krzyżowe przesunięte
  i dwie kontrole wewnątrz drugiego słowa nonce.
- Pochodne drugiego rzędu policzono z XOR czterech strumieni przed obliczeniem
  HW. Kontrola SHAKE256 współdzieli losowy stan roboczy między finalizacjami
  i otrzymuje te same rzeczywiste stany początkowe co szyfr.

Protokół `ARX_FEEDFORWARD_PROTOCOL.txt` zapisano przed generacją nowej kohorty.
SHA-256: `b416c7fb7b6697e26c4707b9e6c70981245f22eaecd243c480319ea393090ef8`.
Jest to lokalnie ustalony protokół prospektywny, nie publiczna prerejestracja.
Oddzielne indeksy 1080–1081 służyły wyłącznie próbie wykonania w `/tmp`.

## Cztery zaplanowane testy

Wspólna rodzina Holma obejmuje cztery dwustronne testy dla dwóch rund.
Pierwsze trzy dotyczą entropii przy segmentacji 128-bitowej. J jest zmianą
średniej HW drugiej pochodnej w 32-bitowym słowie wyjściowym 7, po odjęciu
analogicznej zmiany w sprzężonej kontroli. Wszystkie przedziały są punktowymi
95-procentowymi przedziałami z 5000 bootstrapów całych par kluczy.

| Test | Wynik [95% CI] | Skorygowane p |
| --- | --- | --- |
| Salsa20 G bez feed-forward | 0.729403 [0.723915, 0.734931] bitu entropii | 0.000040 |
| Salsa20 G: dodawanie minus brak feed-forward | 0.058651 [0.055348, 0.062016] bitu entropii | 0.000040 |
| ChaCha20 G: dodawanie minus brak feed-forward | −0.002929 [−0.006516, 0.000679] bitu entropii | 0.107769 |
| Salsa20 interakcja J | 0.709671 [0.682635, 0.736861] zmienionego bitu na słowo | 0.000040 |

Wartość około 0.000040 jest progiem rozdzielczości symulacji 100 000 zmian
znaków po korekcie dla czterech testów. Asymetria Salsa20 istnieje już przed
feed-forward; dodawanie ją zwiększa. Surowa średnia HW drugiej pochodnej w
słowie 7 wzrasta z dokładnego zera do 0.724194; po odjęciu różnicy referencji
otrzymujemy J powyżej. Żadna z tych liczb nie jest przewagą ataku.

Brak rozstrzygnięcia w ChaCha20 dotyczy planowanego kontrastu przy 128 bitach.
Opisowe zmiany entropii przy 32 i 64 bitach mają przedziały wykluczające zero.
Przy czterech rundach duże sygnatury słabną, lecz nie wszystkie małe
przedziały opisowe obejmują zero. Tekst nie deklaruje równoważności z kontrolą.

## Wyprowadzenia i kontrole dokładne

Druga pochodna wariantów bez feed-forward i z XOR jest identyczna bitowo,
ponieważ stan początkowy jest afiniczny względem nonce. Dla Salsa20/2
wyprowadzono dodatkowo warunkową afiniczność
`((u XOR C) + u) mod 2^32` w u przy ustalonym C oraz dokładny wzór na mieszaną
pochodną przy zmianie C przez pierwsze słowo nonce. To pozwala odróżnić
kontrole wewnątrz jednego słowa od interakcji między słowami.

Wszystkie 11 grup kontroli deterministycznych zakończyło się bez naruszeń,
w tym po 12 451 840 równości none/XOR dla szyfrów i kontroli oraz 184 320
przewidywań mieszanych pochodnych modularnych. Te liczności nie zwiększają
statystycznej liczby replikacji: nadal wynosi ona 80 par kluczy.

## Weryfikacja i pliki

- `python3 run.py vectors`: 32 sprawdzenia zakończone powodzeniem.
- `python3 run.py audits`: wszystkie wcześniejsze audyty oraz nowy audyt
  feed-forward zakończone powodzeniem.
- Niezależny `tools/audit_arx_feedforward.py` nie importuje generatora ani
  jego funkcji rund, agregacji czy wnioskowania. Odtworzył 52 736 bloków dla
  kluczy 1000 i 1079 oraz odpowiednie strumienie kontroli. Sprawdził zapisane
  świadectwa uint32 w całej kohorcie, sześć rodzin tabel, przedziały i testy.
  Maksymalna różnica numeryczna wyniosła 1.60 × 10⁻¹⁴.
- Dane, checkpointy, manifesty i raport audytu znajdują się w
  `data/arx_feedforward_results/`. Opis osi zawiera tamtejszy `README.md`.
- `main.pdf`: 28 stron, 40 pozycji bibliograficznych; kompilacja bez
  ostrzeżeń, przepełnień i brakujących odsyłaczy. Obejrzano metody na stronach
  12–14, wyniki na stronach 19–21, tabele 8–9 oraz nową figurę 2.
- Nowe sekcje źródłowe to `arx_feedforward_methods.tex` i
  `arx_feedforward_results.tex`; figurę odtwarza `make_feedforward_figure.py`.
  Zaktualizowano abstrakt, wkład pracy, dyskusję, wnioski, README i list
  przewodni oraz skrypty pakowania v0.16.0.

## Zachowanie wcześniejszej pracy

Zachowano bez zmian pliki `biblio.bib`, `related_work_comparison.tex` i
`RELATED_WORK_NOTES.md` z uzupełnieniami autora, w tym 16 nowymi pozycjami.
Dodane przez autora akapity dyskusji również pozostają w tekście. Nowe
badanie odwołuje się do istniejącej analizy różnicowej wyższego rzędu i nie
przedstawia samej drugiej pochodnej jako nowej metody kryptanalizy.

Nie zmieniono wcześniejszych surowych danych, protokołów ani hashowanych
zależności generatorów. Starsze archiwa są wersjami historycznymi. Nowe
pakiety mają nazwy `electronics_iv_diffusion_submission_v0.16.0.zip` oraz
`iv_diffusion_research_review_v0.16.0.zip`.
