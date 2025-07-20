import { useGetFlowsQuery } from "../api";
import type { Flow } from "../types";

export function Fingerprints() {
  const { data: flows, isLoading } = useGetFlowsQuery({});

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-4xl font-bold">Loading...</span>
      </div>
    );
  }

  // Build a mapping from fingerprint to flows that have it
  const fingerprintMap: Record<string, { flows: Flow[] }> = {};

  if (flows && Array.isArray(flows)) {
    flows.forEach((flow) => {
      // Assume flow.fingerprints is an array of strings
      if (Array.isArray(flow.fingerprints)) {
        flow.fingerprints.forEach((fp: string) => {
          if (!fingerprintMap[fp]) {
            fingerprintMap[fp] = { flows: [] };
          }
          fingerprintMap[fp].flows.push(flow);
        });
      }
    });
  }

  // Get latest fingerprints (sorted by number of flows, descending)
  const sortedFingerprints = Object.entries(fingerprintMap).sort(
    (a, b) => b[1].flows.length - a[1].flows.length,
  );

  return (
    <div className="mx-8 mt-10">
      <h2 className="text-3xl font-bold mb-6 text-center">Fingerprints</h2>
      {sortedFingerprints.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {sortedFingerprints.map(([fingerprint, { flows }]) => (
            <FingerprintSection
              key={fingerprint}
              fingerprint={fingerprint}
              flows={flows}
            />
          ))}
        </div>
      ) : (
        <div className="text-center text-gray-500 dark:text-gray-400 text-lg">
          No fingerprints found.
        </div>
      )}
    </div>
  );
}

function FingerprintSection({
  fingerprint,
  flows,
}: {
  fingerprint: string;
  flows: Flow[];
}) {
  return (
    <section
      key={fingerprint}
      className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow p-5 flex flex-col"
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="font-mono text-blue-700 dark:text-blue-300 break-all text-sm">
          {fingerprint}
        </span>
        <span className="ml-2 bg-blue-100 dark:bg-blue-900 dark:text-blue-200 text-blue-800 text-xs font-semibold px-2.5 py-0.5 rounded">
          {flows.length} flow{flows.length !== 1 ? "s" : ""}
        </span>
      </div>
      <div>
        <ul className="space-y-1">
          {flows.slice(0, 3).map((flow, idx: number) => (
            <li key={flow._id || idx}>
              Flow
              <a
                href={flow._id ? `/flow/${flow._id}` : "#"}
                className="text-blue-600 dark:text-blue-400 hover:underline ms-2"
              >
                {flow._id}
              </a>
              {flow.time && (
                <span className="text-gray-500 dark:text-gray-400 text-xs ms-2">
                  {new Date(flow.time).toLocaleString()}
                </span>
              )}
            </li>
          ))}
          {flows.length > 3 && (
            <li className="text-gray-500 dark:text-gray-400 text-xs">
              +{flows.length - 3} more
            </li>
          )}
        </ul>
      </div>
    </section>
  );
}
