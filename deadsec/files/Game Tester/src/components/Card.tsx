'use client';

import styles from '../styles/Card.module.css';

type CardProps = {
  card: { id: number; img: string };
  flipped: boolean;
  matched: boolean;
  onClick: () => void;
};

export default function Card({ card, flipped, matched, onClick }: CardProps) {
  return (
    <div
      className={`${styles.card} ${flipped || matched ? styles.flipped : ''}`}
      onClick={onClick}
      tabIndex={0}
      role="button"
      aria-pressed={flipped || matched}
    >
      <div className={styles.inner}>
        <div className={styles.front}></div>
        <div className={styles.back}>
          <img src={card.img} alt="card" />
        </div>
      </div>
    </div>
  );
} 