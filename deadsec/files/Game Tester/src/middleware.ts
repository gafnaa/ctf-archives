import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
  const AdminKey = Math.random().toString(36).slice(2, 18);
  const key = request.nextUrl.searchParams.get('key');
  if (key !== AdminKey) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/admin/:path*'],
}; 