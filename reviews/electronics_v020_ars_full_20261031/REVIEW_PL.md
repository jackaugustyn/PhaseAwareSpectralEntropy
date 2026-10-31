# Recenzja ARS wersji 0.20 — 31 października 2026

**Rekomendacja: Minor Revision — drobne poprawki.** Pięć ról modelowego panelu ukończyło recenzję. Panel zgłosił sześć uwag kategorii Minor, bez usterek Critical lub Major. Zalecenia nie wymagają nowych eksperymentów ani suplementu. Recenzowany artykuł ma 11 stron, w tym 40 pozycji bibliograficznych.

Walidacja kontraktu, pięciu planów i pięciu raportów, wyprowadzenia rekomendacji, powiązania listy zmian z manuskryptem oraz zapisu pochodzenia ocen zakończyła się powodzeniem. Użyty Python poprawnie obsługuje jsonschema 4.26.0 i Draft202012Validator. Jest to nowa pełna recenzja wersji 0.20, a nie uzupełnienie brakujących dokumentów wcześniejszej recenzji.

Panel uznał za spójny główny przekaz: lokalne własności algebraiczne, kontrolowane interwencje i rekonstrukcja widma wspierają diagnostykę dyfuzji o wyraźnie ograniczonym zakresie. Nie stanowią dowodu podatności pełnorundowych szyfrów.

| Odnośnik | Zalecenie | Status w recenzji |
|---|---|---|
| REV-EIC-W1 | Pokazać porównanie obu modeli dla wszystkich sześciu par szyfr–szerokość w zwartej tabeli lub jednoznacznie opisanych zestawach wartości, wykorzystując istniejące wyniki. | Zalecane |
| REV-EIC-W2 | Skrócić omówienie badań pomocniczych do dwóch wniosków: roli inicjalizacji oraz tego, że brak sygnału diagnostycznego nie dowodzi bezpieczeństwa. | Zalecane |
| REV-R1-W1 | Doprecyzować nagłówek i podpis tabeli 2: wartości po korekcie Holma są kalibracją sign-flip zależną od założenia niezmienniczości rozkładu przy zmianie znaków. | Wymagane |
| REV-R1-W2 | Podać, że stosowano 95% przedziały bootstrapowe metodą percentylową: kwantyle 0,025 i 0,975, czyli percentyle 2,5 i 97,5. Zachować opis jednostki losowania i warunkowego charakteru niepewności predykcji. | Wymagane |
| REV-R1-W3 | Przed publikacją zapewnić trwały dostęp do konkretnej wersji danych i kodu oraz uaktualnić Data Availability Statement. DOI jest jedną z możliwości. | Wymagane przed publikacją |
| REV-R3-W1 | Krótko wyjaśnić sens afiniczności względem XOR i rzędu mapy oraz różnicę między rzędem a średnią liczbą zmienionych bitów. | Zalecane |

Kolejność odtwarza źródła uwag i nie jest rankingiem prac. Każdą uwagę zgłosiła jedna rola; brak komentarza innych ról nie oznacza jej niezależnego potwierdzenia. Rekomendacja wynika wyłącznie z warunku F5 kontraktu. Oceny pewności recenzentów nie służyły jako wagi.

**Zakres oceny:** nie zweryfikowano aktualnych kryteriów Electronics ani nowości i pierwszeństwa na podstawie pełnych tekstów cytowanych prac. Nie przeprowadzono pełnego powtórzenia symulacji. Rozdzielenie ról i kontekstów jest udokumentowane, ale niezależność rodzin modeli oraz pełne odizolowanie od plików innych ról pozostają niepotwierdzone. Status kalibracji panelu: NOT_CALIBRATED. Ta recenzja nie jest decyzją redakcji ani oszacowaniem prawdopodobieństwa przyjęcia.

Doradczy audyt twierdzeń recenzentów nie został uruchomiony, ponieważ środowisko nie zapewnia wymaganej izolacji narzędzi. Sieciowej kontroli proponowanych odniesień nie uruchamiano. Kontrola skrótów została wykonana z częściowym pokryciem; jej komunikat o abstrakcie wynika z nierozpoznania tej części w ekstrakcji PDF i nie oznacza, że w artykule brakuje abstraktu. Wyniki tych załączników nie zmieniają decyzji ani listy poprawek.

Pełna dokumentacja: [list decyzyjny](synthesis.md), [lista zmian w JSON](revision_roadmap.json), [raport strukturalny](review_report.json), [podsumowanie walidacji](validation_summary.md). Manuskrypt i wcześniejsze pakiety pozostały niezmienione.
