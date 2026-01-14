import { NextRequest, NextResponse } from 'next/server';
import { analyzeContract } from '@/lib/analyzer';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { code } = body;

    if (!code || typeof code !== 'string') {
      return NextResponse.json(
        { error: 'Missing or invalid "code" field in request body' },
        { status: 400 }
      );
    }

    if (code.trim().length === 0) {
      return NextResponse.json(
        { error: 'Code cannot be empty' },
        { status: 400 }
      );
    }

    const result = analyzeContract(code);

    return NextResponse.json(result);
  } catch (error) {
    console.error('Analysis error:', error);

    const message = error instanceof Error ? error.message : 'Unknown error';

    // Check if it's a parsing error
    if (message.includes('Parse') || message.includes('parse')) {
      return NextResponse.json(
        { error: `Failed to parse Solidity code: ${message}` },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: `Analysis failed: ${message}` },
      { status: 500 }
    );
  }
}
