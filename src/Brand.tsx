export default function Brand({
  onClick,
  compact = false,
}: {
  onClick: () => void;
  compact?: boolean;
}) {
  return (
    <button
      className={`site-brand ${compact ? "compact-brand" : ""}`}
      onClick={onClick}
      aria-label="Phish and Chips home"
    >
      <img
        className="brand-mark"
        src={brandMark}
        width="36"
        height="33"
        alt=""
        aria-hidden="true"
      />
      <span>
        phish<span className="site-brand-amp">&</span>chips<span className="site-brand-dot">.</span>
      </span>
    </button>
  );
}
import brandMark from "./assets/phish-and-chips.svg";
