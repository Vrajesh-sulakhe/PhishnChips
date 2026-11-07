export default function CubeFallback() {
  return (
    <div className="cube-fallback">
      {Array.from({ length: 6 }, (_, i) => (
        <span className={`cube-face cube-face-${i}`} key={i} />
      ))}
    </div>
  );
}
