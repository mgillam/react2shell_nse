export const dynamic = 'force-dynamic';

export default function Status() {
  return (
    <main>
      <h1>Status</h1>
      <p>App is running. Time: {new Date().toISOString()}</p>
    </main>
  );
}
