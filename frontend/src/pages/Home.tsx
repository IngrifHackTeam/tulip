import { useSearchParams } from "react-router";
import { Link } from "react-router";

const shortcutTableData = [
  [
    { key: "j/k", action: "Down/Up in FlowList" },
    { key: "s", action: "Focus search bar" },
    { key: "esc", action: "Unfocus search bar" },
    { key: "i/o", action: "Toggle flag in/out filters" },
  ],
  [
    { key: "h/l", action: "Up/Down in Flow" },
    { key: "a", action: "Last 5 ticks" },
    { key: "c", action: "Clear time selection" },
    { key: "r", action: "Refresh flows" },
  ],
  [
    { key: "d", action: "Diff view" },
    { key: "f", action: "Load flow to first diff slot" },
    { key: "g", action: "Load flow to second diff slot" },
  ],
];

function generateShortcutTable(data: { key: string; action: string }[][]) {
  return (
    <div className="flex flex-row gap-4">
      {data.map((table) => (
        <table
          key={table.map((row) => row.key).join("-")}
          className="border-collapse border border-slate-500 table-auto"
        >
          <thead>
            <tr>
              <th className="border border-slate-600 px-4">Key</th>
              <th className="border border-slate-600 px-4">Action</th>
            </tr>
          </thead>
          <tbody>
            {table.map((row) => (
              <tr key={row.action}>
                <td className="border border-slate-700 px-4">{row.key}</td>
                <td className="border border-slate-700 px-4">{row.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}

export function Home() {
  const [searchParams] = useSearchParams();

  return (
    <>
      <div className="p-4 flex flex-col justify-center items-center h-full">
        <span className="text-9xl mb-4">🌷</span>
        <h1 className="text-5xl text-gray-600">Welcome to Tulip</h1>
        <span className="text-xl">(Ulisse Edition)</span>

        <div className="flex mt-8">
          <Link to={`/corrie?${searchParams}`}>
            <div className="bg-blue-100 dark:bg-blue-900 text-blue-900 dark:text-blue-100 rounded-md border border-blue-300 dark:border-blue-800 px-6 py-3 text-lg text-center hover:bg-blue-200 dark:hover:bg-blue-800 cursor-pointer transition-colors">
              Graph view
            </div>
          </Link>
          <Link to={`/fingerprints?${searchParams}`}>
            <div className="bg-green-100 dark:bg-green-900 text-green-900 dark:text-green-100 rounded-md border border-green-300 dark:border-green-800 px-6 py-3 text-lg ms-2 text-center hover:bg-green-200 dark:hover:bg-green-800 cursor-pointer transition-colors">
              Fingerprints
            </div>
          </Link>
        </div>

        <h1 className="text-2xl text-gray-500 mt-8">Shortcut reference:</h1>
        {generateShortcutTable(shortcutTableData)}
      </div>
    </>
  );
}
