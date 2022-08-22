export class Class {
  hello = 'this is a test'
  world(number): number {
    return parseFloat(number) + 1
  }
}

export function outsider() {
  return 'hello, outsider...'
}
