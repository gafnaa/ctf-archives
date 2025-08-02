'use client';

import { useState, useEffect } from 'react';
import Card from '../components/Card';
import cardsData from '../data/cards.json';
import styles from '../styles/Card.module.css';

type CardType = {
  id: number;
  pairId: string;
  img: string;
};

function shuffle(array: CardType[]) {
  return array
    .map((value) => ({ value, sort: Math.random() }))
    .sort((a, b) => a.sort - b.sort)
    .map(({ value }) => value);
}

function chunk<T>(array: T[], size: number): T[][] {
  return Array.from({ length: Math.ceil(array.length / size) }, (_, i) =>
    array.slice(i * size, i * size + size)
  );
}

export default function Home() {
  const [cards, setCards] = useState<CardType[]>([]);
  const [flipped, setFlipped] = useState<number[]>([]);
  const [matched, setMatched] = useState<number[]>([]);
  const [lock, setLock] = useState(false);
  const [showPopup, setShowPopup] = useState(false);

  useEffect(() => {
    setCards(shuffle(cardsData));
  }, []);

  useEffect(() => {
    if (flipped.length === 2) {
      setLock(true);
      const [first, second] = flipped;
      const firstCard = cards.find((c) => c.id === first);
      const secondCard = cards.find((c) => c.id === second);

      if (firstCard && secondCard && firstCard.pairId === secondCard.pairId) {
        setTimeout(() => {
          setMatched((prev) => [...prev, first, second]);
          setFlipped([]);
          setLock(false);
        }, 800);
      } else {
        setTimeout(() => {
          setFlipped([]);
          setLock(false);
        }, 800);
      }
    }
  }, [flipped, cards]);

  useEffect(() => {
    if (matched.length === cards.length && cards.length > 0) {
      setShowPopup(true);
    }
  }, [matched, cards]);

  const handleCardClick = (id: number) => {
    if (lock) return;
    if (flipped.includes(id) || matched.includes(id)) return;
    if (flipped.length === 2) return;
    setFlipped((prev) => [...prev, id]);
  };

  const handleClosePopup = () => {
    setShowPopup(false);
    setCards(shuffle(cardsData));
    setMatched([]);
    setFlipped([]);
    setLock(false);
  };

  const rows = chunk(cards, 4);

  return (
    <main style={{ textAlign: 'center', marginTop: 40 }}>
      <h1 className={styles.title}>Memory Card Game</h1>
      <div>
        {rows.map((row, rowIdx) => (
          <div key={rowIdx} style={{ display: 'flex', justifyContent: 'center' }}>
            {row.map((card) => (
              <Card
                key={card.id}
                card={card}
                flipped={flipped.includes(card.id)}
                matched={matched.includes(card.id)}
                onClick={() => handleCardClick(card.id)}
              />
            ))}
          </div>
        ))}
      </div>
      {showPopup && (
        <div className={styles.popup}>
          <div className={styles['popup-content']}>
            <h2>Congratulations!</h2>
            <p>You matched all the cards!<br />Try again?</p>
            <button onClick={handleClosePopup}>Restart</button>
          </div>
        </div>
      )}
    </main>
  );
} 