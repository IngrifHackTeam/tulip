import { useGetServicesQuery, useGetFlagRegexQuery } from "../api";

export function Settings() {
  return (
    <div className="flex flex-col items-center mt-16 mx-16 p-4">
      <h1 className="text-4xl font-bold mb-4">Settings</h1>
      <FlagRegexDisplay />
      <Services />
    </div>
  );
}

function Subtitle({
  children,
  icon,
}: {
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <h2 className="text-2xl font-bold mb-6 text-blue-600 dark:text-blue-500 font-mono tracking-wide flex items-center gap-2">
      {icon}
      {children}
    </h2>
  );
}

function LoadingView({ children }: { children?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-center my-4">
      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500 dark:border-blue-500 mr-2"></div>
      <span className="text-gray-500 dark:text-gray-400 font-mono text-base">
        {children ?? "Loading..."}
      </span>
    </div>
  );
}

function ErrorView({
  error,
  children,
}: {
  error: unknown;
  children?: React.ReactNode;
}) {
  return (
    <div className="bg-red-50 dark:bg-red-100/10 border border-red-400 text-red-700 dark:text-red-400 px-3 py-1 rounded font-mono text-xs my-2">
      <span className="font-bold">{children ?? "Error:"}</span>{" "}
      {JSON.stringify(error)}
    </div>
  );
}

function FlagRegexDisplay() {
  const { data, isLoading, error } = useGetFlagRegexQuery();

  if (isLoading) {
    return <LoadingView>Loading regex flag...</LoadingView>;
  }

  if (error) {
    return <ErrorView error={error}>Error loading regex flag:</ErrorView>;
  }

  return (
    <div className="my-4 w-full">
      <Subtitle
        icon={
          <span role="img" aria-label="flag" className="text-2xl">
            🏳️
          </span>
        }
      >
        Current Flag Regex
      </Subtitle>
      <div className="bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded px-3 py-2 font-mono text-sm text-gray-800 dark:text-gray-100 break-all">
        {data ?? (
          <span className="italic text-gray-400">No regex flag found.</span>
        )}
      </div>
    </div>
  );
}

function Services() {
  const { data, isLoading, error } = useGetServicesQuery();

  if (isLoading) {
    return <LoadingView>Loading services...</LoadingView>;
  }

  if (error) {
    return <ErrorView error={error} />;
  }

  if (!data || !Array.isArray(data) || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-32">
        <span className="text-gray-500 dark:text-gray-400 font-mono text-lg">
          No services found.
        </span>
      </div>
    );
  }

  return (
    <div className="mt-8 w-full">
      <Subtitle
        icon={
          <span role="img" aria-label="server" className="text-2xl">
            🖥️
          </span>
        }
      >
        Available Services
      </Subtitle>
      <div className="overflow-x-auto rounded-lg">
        <table className="min-w-full bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 font-mono text-sm border border-gray-200 dark:border-gray-700">
          <thead>
            <tr>
              <th className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 text-left">
                Service
              </th>
              <th className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 text-left">
                IP Address
              </th>
              <th className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 text-left">
                Port
              </th>
            </tr>
          </thead>
          <tbody>
            {data.map((service) => (
              <tr
                key={service.name}
                className="hover:bg-gray-100 dark:hover:bg-gray-800 transition"
              >
                <td className="px-4 py-2 border-b border-gray-100 dark:border-gray-800 font-semibold text-blue-700 dark:text-blue-300">
                  <span className="inline-block bg-blue-100/60 dark:bg-blue-900/60 px-2 py-1 rounded">
                    {service.name}
                  </span>
                </td>
                <td className="px-4 py-2 border-b border-gray-100 dark:border-gray-800">
                  <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                    {service.ip}
                  </code>
                </td>
                <td className="px-4 py-2 border-b border-gray-100 dark:border-gray-800">
                  <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                    {service.port}
                  </code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
