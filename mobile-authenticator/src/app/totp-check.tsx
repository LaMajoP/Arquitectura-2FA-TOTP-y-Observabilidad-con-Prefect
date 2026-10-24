
import { useEffect, useState } from "react";
import { ScrollView, Text, View } from "react-native";
import { generateTOTP, secondsRemaining } from "../artifacts/totp";

const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const VECTORS = [
  { time: 59, expected: "287082" },
  { time: 1111111109, expected: "081804" },
  { time: 1111111111, expected: "050471" },
  { time: 1234567890, expected: "005924" },
  { time: 2000000000, expected: "279037" },
  { time: 20000000000, expected: "353130" },
];

export default function TotpCheck() {
  const [results, setResults] = useState<string[]>([]);
  const [liveCode, setLiveCode] = useState("");
  const [remaining, setRemaining] = useState(30);

  useEffect(() => {
    let active = true;

    async function checkVectors() {
      const output = [];
      for (const vector of VECTORS) {
        const code = await generateTOTP(
          SECRET,
          vector.time * 1000
        );
        output.push(
          `${vector.time}: ${code} — ${
            code === vector.expected ? "CORRECTO" : "ERROR"
          }`
        );
      }
      if (active) setResults(output);
    }

    checkVectors().catch((error) => {
      if (active) setResults([String(error)]);
    });

    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    let lastCounter = -1;

    async function update() {
      const now = Date.now();
      const counter = Math.floor(now / 30000);
      if (active) setRemaining(secondsRemaining(now));

      if (counter !== lastCounter) {
        lastCounter = counter;
        try {
          const code = await generateTOTP(SECRET, now);
          if (active && Math.floor(Date.now() / 30000) === counter) {
            setLiveCode(code);
          }
        } catch (error) {
          if (active) setLiveCode(String(error));
        }
      }
    }

    update();
    const timer = setInterval(update, 500);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <ScrollView contentContainerStyle={{ padding: 24, gap: 12 }}>
      <Text style={{ fontSize: 24, fontWeight: "bold" }}>
        Comprobación TOTP
      </Text>

      {results.map((result, index) => (
        <Text key={index}>{result}</Text>
      ))}

      <View style={{ marginTop: 30 }}>
        <Text>Código actual:</Text>
        <Text style={{ fontSize: 40, fontWeight: "bold" }}>
          {liveCode}
        </Text>
        <Text>Segundos restantes: {remaining}</Text>
      </View>
    </ScrollView>
  );
}
