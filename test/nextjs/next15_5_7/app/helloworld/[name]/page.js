export default async function HelloWorld({ params }) {
  const { name } = await params;
  return (
    <main>
      <h1>Hello, {name}!</h1>
    </main>
  );
}

export async function generateStaticParams() {
  return [];
}
