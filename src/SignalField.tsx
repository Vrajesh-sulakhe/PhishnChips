const random = (seed: number) => {
  const value = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
  return value - Math.floor(value);
};

export default function SignalField({ className = "" }: { className?: string }) {
  return (
    <div className={`signal-field ${className}`} aria-hidden="true">
      <svg viewBox="0 0 800 950" fill="none" preserveAspectRatio="xMidYMid slice">
        <defs>
          <linearGradient
            id="signalRed"
            x1="0"
            y1="0"
            x2="800"
            y2="900"
            gradientUnits="userSpaceOnUse"
          >
            <stop stopColor="#fa6057" />
            <stop offset=".5" stopColor="#ba251e" />
            <stop offset="1" stopColor="#591511" />
          </linearGradient>
          <filter id="signalGlow">
            <feGaussianBlur stdDeviation="2.5" />
          </filter>
        </defs>
        <g opacity=".16" stroke="#cb3b32" strokeWidth=".5">
          {Array.from({ length: 25 }, (_, i) => (
            <path key={i} d={`M${i * 35} 0v950M0 ${i * 42}h800`} />
          ))}
        </g>
        {Array.from({ length: 44 }, (_, column) => {
          const x = 32 + column * 18;
          return (
            <g
              key={column}
              className="signal-column"
              style={{
                animationDelay: `${-random(column + 9) * 10}s`,
                animationDuration: `${14 + random(column + 7) * 15}s`,
              }}
            >
              <path
                d={`M${x} ${random(column + 8) * 200}v${250 + random(column + 1) * 650}`}
                stroke={column % 4 === 0 ? "#ef4b3e" : "#77534d"}
                strokeOpacity={column % 4 === 0 ? ".5" : ".22"}
                strokeWidth={column % 7 === 0 ? "2" : ".6"}
              />
              {Array.from({ length: 22 }, (_, row) => {
                const seed = column * 24 + row + 1;
                const y = row * 45 + random(seed) * 24;
                const red = random(seed + 3) > 0.55;
                return (
                  <g key={row} opacity={0.18 + random(seed + 2) * 0.67}>
                    {random(seed + 1) > 0.6 ? (
                      <text
                        x={x + 3}
                        y={y}
                        fill={red ? "#e55a4c" : "#a58e87"}
                        fontFamily="monospace"
                        fontSize={6 + random(seed + 4) * 4}
                      >
                        {["01", "0x", "{}", "//", "10", "∷"][Math.floor(random(seed + 5) * 6)]}
                      </text>
                    ) : (
                      <rect
                        className="signal-packet"
                        style={{
                          animationDelay: `${-random(seed + 12) * 18}s`,
                          animationDuration: `${7 + random(seed + 13) * 12}s`,
                          animationDirection: column % 3 === 0 ? "reverse" : "normal",
                        }}
                        x={x}
                        y={y}
                        width={random(seed + 6) > 0.7 ? 6 : 2}
                        height={3 + random(seed + 4) * 20}
                        fill={red ? "#ec4d3e" : "#8f7069"}
                      />
                    )}
                  </g>
                );
              })}
            </g>
          );
        })}
        <g stroke="url(#signalRed)">
          <path
            d="M60 162h252v73h282v-104h146M12 476h192V330h301v307h241M154 884V746h246v-84h288M92 44v264h195v498h369"
            strokeWidth="1"
            opacity=".6"
          />
          <path
            d="M110 280h590M368 30v835M605 122v655M201 625h590"
            strokeWidth=".6"
            opacity=".45"
          />
          <path
            d="M285 235h277M204 476v-94M400 746h169"
            stroke="#f06a57"
            strokeWidth="3"
            opacity=".7"
            filter="url(#signalGlow)"
          />
          <path
            d="M285 235h277M204 476v-94M400 746h169"
            stroke="#ec6353"
            strokeWidth="1.4"
            opacity=".9"
          />
        </g>
        <g fill="#ed5c4c">
          {[
            [312, 162],
            [204, 476],
            [505, 330],
            [400, 746],
            [605, 280],
            [368, 625],
          ].map(([x, y], i) => (
            <g key={i}>
              <circle cx={x} cy={y} r="3" />
              <circle cx={x} cy={y} r="8" stroke="#c83f33" strokeWidth=".6" fill="none" />
            </g>
          ))}
        </g>
        <g transform="translate(366 405)">
          <rect
            x="-54"
            y="-54"
            width="108"
            height="108"
            rx="2"
            stroke="#bf3b30"
            strokeOpacity=".5"
            fill="#160807"
            fillOpacity=".85"
          />
          <path
            d="M0-29-24-19V0c0 15 10 24 24 31C14 24 24 15 24 0v-19L0-29Z"
            stroke="#ec685b"
            strokeWidth="1.2"
          />
          <path d="m-10 0 7 7L12-9" stroke="#f39d8b" strokeWidth="2" />
          <path d="M-65-44v-21h21m88 0h21v21m0 88v21H44m-88 0h-21V44" stroke="#e44a3b" />
        </g>
        <path className="signal-scan" d="M0 260h800" stroke="#e74333" strokeOpacity=".35" />
      </svg>
      <div className="signal-vignette" />
    </div>
  );
}
