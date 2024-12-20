export default function Example() {
  return (
    <>
      {/*
        This example requires updating your template:

        ```
        <html class="h-full">
        <body class="h-full">
        ```
      */}
      <main className="relative isolate h-screen">
        <img
          alt=""
          src="https://images.unsplash.com/photo-1545972154-9bb223aac798?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=3050&q=80&exp=8&con=-15&sat=-75"
          className="absolute inset-0 -z-10 size-full object-cover object-top"
        />
        <div className="mx-auto max-w-7xl px-6 py-32 text-center sm:py-40 lg:px-8">
          <p className="text-base/8 font-semibold text-white">404</p>
          <h1 className="mt-4 text-balance text-5xl font-semibold tracking-tight text-white sm:text-7xl">
            Halaman sedang dalam pembangunan
          </h1>
          <p className="mt-6 text-pretty text-lg font-medium text-white/70 sm:text-xl/8">
            Silahkan hubungi kami langsung untuk pertanyaan
          </p>
          <div className="mt-10 flex justify-center">
            <a
              target="_blank"
              href="https://wa.me/+6287846854410/?text=Halo FCC Indo Jaya, saya membuka website anda dan ingin bertanya"
              className="relative z-10 inline-block rounded-md border border-transparent bg-indigo-600 px-8 py-3 text-center font-medium text-white hover:bg-indigo-700"
            >
              <div className="flex items-center justify-center">
                <img src="/home/wa.png" className="mr-2 h-8 w-auto"></img>
                Hubungi Kami
              </div>
            </a>
          </div>
        </div>
      </main>
    </>
  );
}
