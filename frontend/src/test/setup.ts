import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => cleanup())
// jsdom does not implement layout APIs used for scrolling evidence into view
Element.prototype.scrollIntoView = function scrollIntoView() {}
