import { describe, it, expect } from 'vitest';
import { isPlainObject } from '../src/validation.js';

describe('isPlainObject', () => {
  it('should return false for undefined', () => {
    expect(isPlainObject(undefined)).toBe(false);
  });

  it('should return false for number', () => {
    expect(isPlainObject(42)).toBe(false);
  });

  it('should return false for string', () => {
    expect(isPlainObject('hello')).toBe(false);
  });

  it('should return true for Object.create(null)', () => {
    expect(isPlainObject(Object.create(null) as unknown)).toBe(true);
  });

  it('should return false for class instance', () => {
    class Custom {
      value = 1;
    }
    expect(isPlainObject(new Custom())).toBe(false);
  });

  it('should return true for plain object literal', () => {
    expect(isPlainObject({ a: 1, b: 'x' })).toBe(true);
  });

  it('should return false for null', () => {
    expect(isPlainObject(null)).toBe(false);
  });

  it('should return false for array', () => {
    expect(isPlainObject([1, 2, 3])).toBe(false);
  });

  it('should return false for Map instance', () => {
    expect(isPlainObject(new Map())).toBe(false);
  });
});
